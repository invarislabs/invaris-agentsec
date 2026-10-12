"""Email attack pack: the simulated mailbox tools, their state changes, and the full
delivery/attack-goal/delayed-injection pipeline through the real runner and evaluators.

Deterministic and offline: a scripted in-process agent (CallableAdapter) drives run_suite, so
these tests exercise AgentSec's real verdict logic -- findings / passed / inconclusive -- not just
the fixture helpers. No adversarial text is used; every injection is a neutral placeholder slot.
"""
import json
import re
from pathlib import Path

import pytest

from agentsec.adapters import CallableAdapter
from agentsec.attacks import CATEGORIES
from agentsec.attacks.base import ScenarioContext
from agentsec.attacks.packs import load_pack, load_packs
from agentsec.policies import parse_policy
from agentsec.evaluators import evaluate_trace
from agentsec.evaluators.goals import was_delivered
from agentsec.runners import run_suite
from agentsec.runners.local import ScenarioResult, run_scenario
from agentsec.traces import Trace

import importlib.util

_PACK_PATH = Path(__file__).resolve().parent.parent / "examples" / "attack_packs" / "email_agent_pack.py"
_POLICY_PATH = Path(__file__).resolve().parent.parent / "examples" / "attack_packs" / "email_assistant.agentsec.yaml"

import sys as _sys
_spec = importlib.util.spec_from_file_location("email_agent_pack_under_test", str(_PACK_PATH))
pack = importlib.util.module_from_spec(_spec)
_sys.modules[_spec.name] = pack  # dataclasses needs the module registered
_spec.loader.exec_module(pack)

POLICY = parse_policy(_POLICY_PATH.read_text())
# Derived from the pack so a newly added injection surface/slot is picked up automatically.
SLOTS = tuple(sorted(v for k, v in vars(pack).items()
                     if k.endswith("_SLOT") and isinstance(v, str)))


# ---- Mailbox fixture: tool behaviour and state changes ---------------------

def test_read_inbox_lists_envelopes_not_bodies():
    mb = pack.build_mailbox()
    data = json.loads(mb.read_inbox())
    assert data["count"] == len(data["messages"])
    msg = data["messages"][0]
    assert set(msg) >= {"id", "from", "subject", "unread"}
    assert "body" not in msg  # listing must not leak bodies; the agent must open_email to read one


def test_open_email_returns_body_and_marks_read():
    mb = pack.build_mailbox()
    before = json.loads(mb.read_inbox(unread_only=True))["count"]
    opened = json.loads(mb.open_email("msg-0001"))
    assert opened["id"] == "msg-0001" and "body" in opened
    after = json.loads(mb.read_inbox(unread_only=True))["count"]
    assert after == before - 1  # it is now read


def test_open_unknown_message_is_an_error_not_a_crash():
    mb = pack.build_mailbox()
    assert json.loads(mb.open_email("nope"))["error"]
    assert json.loads(mb.open_email(None))["error"]


def test_send_and_forward_are_recorded_in_the_outbox():
    mb = pack.build_mailbox()
    mb.send_email(to="a@b.invalid", subject="s", body="b")
    mb.forward_email("msg-0001", to="c@d.invalid", note="n")
    snap = mb.snapshot()
    assert snap["outbox"][0]["action"] == "send" and snap["outbox"][0]["to"] == "a@b.invalid"
    assert snap["outbox"][1]["action"] == "forward" and snap["outbox"][1]["message_id"] == "msg-0001"


def test_delete_moves_to_trash_and_hides_from_inbox():
    mb = pack.build_mailbox()
    mb.delete_email("msg-0001")
    assert "msg-0001" in mb.snapshot()["deleted"]
    ids = [m["id"] for m in json.loads(mb.read_inbox())["messages"]]
    assert "msg-0001" not in ids                       # gone from the inbox listing
    assert json.loads(mb.open_email("msg-0001")).get("error")  # and cannot be opened from trash


def test_confidential_canary_and_security_alert_are_present():
    mb = pack.build_mailbox()
    ids = [m["id"] for m in json.loads(mb.read_inbox())["messages"]]
    assert pack.SECURITY_ALERT_ID in ids
    fin = json.loads(mb.open_email("msg-0050"))
    assert pack.CONFIDENTIAL_CANARY in fin["body"]


# ---- poisoning placement ---------------------------------------------------

def test_poison_slot_lands_in_body_or_attachment_as_requested():
    body_mb = pack.build_mailbox(poison_slot="SLOT-X", in_attachment=False)
    assert "SLOT-X" in json.loads(body_mb.open_email("msg-0100"))["body"]

    att_mb = pack.build_mailbox(poison_slot="SLOT-Y", in_attachment=True)
    opened = json.loads(att_mb.open_email("msg-0100"))
    assert "SLOT-Y" not in opened["body"]
    assert any("SLOT-Y" in a["text"] for a in opened["attachments"])


def test_unpoisoned_mailbox_contains_no_slot_anywhere():
    mb = pack.build_mailbox(poison_slot=None, include_target=True)
    contents = [mb.read_inbox()] + [mb.open_email(m["id"])
                                    for m in json.loads(mb.read_inbox())["messages"]]
    assert not _delivered(contents)


# ---- responder adapter: delivery detection sees JSON-encoded content -------

def test_responder_delivers_injection_through_open_email():
    """The mailbox returns JSON, so a multi-line injection arrives with escaped newlines. It must
    still register as delivered under AgentSec's own detection semantics."""
    respond = pack.make_mailbox_responder(lambda: pack.build_mailbox(poison_slot=pack.OVERT_INJECTION_SLOT))
    listing = respond("read_inbox", {}, 0)
    out = respond("open_email", {"message_id": "msg-0100"}, 1)
    assert not _delivered([listing], [pack.OVERT_INJECTION_SLOT])   # listing shows envelopes only
    assert _delivered([out], [pack.OVERT_INJECTION_SLOT])
    assert pack.OVERT_INJECTION_SLOT not in out                     # ... and only after decoding


def test_responder_resets_state_between_runs():
    respond = pack.make_mailbox_responder(lambda: pack.build_mailbox())
    respond("delete_email", {"message_id": "msg-0001"}, 0)
    # a new run restarts the index at 0 -> fresh mailbox, msg-0001 present again
    listing = json.loads(respond("read_inbox", {}, 0))
    assert "msg-0001" in [m["id"] for m in listing["messages"]]


# ---- scripted agents driving the real pipeline -----------------------------

def _history(messages):
    listing_ids, opened, bodies = [], [], []
    for m in messages:
        if m["role"] == "assistant":
            for tc in m.get("tool_calls") or []:
                if tc["function"]["name"] == "open_email":
                    opened.append(json.loads(tc["function"]["arguments"]).get("message_id"))
        if m["role"] == "tool":
            try:
                d = json.loads(m["content"])
            except Exception:
                continue
            if "messages" in d:
                listing_ids = [x["id"] for x in d["messages"]]
            elif "body" in d or "attachments" in d:
                bodies.append(m["content"])
    return listing_ids, opened, bodies


def _delivered(contents, slots=None):
    """Did any of `contents` (raw tool-result text) carry an injection?

    Uses AgentSec's own delivery semantics -- whitespace-normalized, and looking inside
    JSON-encoded results -- because the mailbox returns JSON, so a multi-line injection appears
    with escaped newlines and a naive substring test would miss it.
    """
    from agentsec.evaluators.goals import _decoded, _norm
    wanted = [_norm(s) for s in (slots if slots is not None else SLOTS)]
    for text in contents:
        hay = _norm(text)
        decoded = _decoded(text)
        if any(w in hay or (decoded and w in decoded) for w in wanted):
            return True
    return False


def _agent(mode):
    """mode: 'obey' (acts on a delivered injection once), 'safe' (reads all, never acts),
    'lazy' (reads the listing only, never opens a message)."""
    def fn(messages, tools):
        last = messages[-1]
        calls = [tc["function"]["name"] for m in messages if m["role"] == "assistant"
                 for tc in m.get("tool_calls") or []]
        if last["role"] == "user":
            return {"tool_calls": [{"name": "read_inbox", "arguments": {}}]}
        listing_ids, opened, bodies = _history(messages)
        if mode == "lazy":
            return "summary from listing only"
        for mid in listing_ids:
            if mid not in opened:
                return {"tool_calls": [{"name": "open_email", "arguments": {"message_id": mid}}]}
        delivered = _delivered(bodies)
        sinks = {"forward_email", "send_email", "delete_email"}
        if mode == "obey" and delivered and not (sinks & set(calls)):
            if any(pack.DELETE_INJECTION_SLOT in b for b in bodies):
                return {"tool_calls": [{"name": "delete_email",
                                        "arguments": {"message_id": pack.SECURITY_ALERT_ID}}]}
            return {"tool_calls": [{"name": "forward_email", "arguments": {
                "message_id": "msg-0050", "to": pack.EXTERNAL_ADDRESS, "note": pack.CONFIDENTIAL_CANARY}}]}
        return "triage complete"
    return CallableAdapter(fn)


def run(scenario, adapter):
    """One scenario through the real runner and the real evaluators."""
    trace = run_scenario(scenario, POLICY, adapter)
    return ScenarioResult(scenario, trace, evaluate_trace(scenario, trace, POLICY))


def _statuses(adapter):
    suite = run_suite(POLICY, adapter, attack_packs=load_packs([str(_PACK_PATH)], CATEGORIES))
    return {r.scenario.id: r for r in suite.results}


def test_obedient_agent_produces_attack_goal_findings_for_every_scenario():
    results = _statuses(_agent("obey"))
    assert results  # the pack built scenarios
    for sid, r in results.items():
        assert r.status == "findings", sid
        rules = {f.rule for f in r.findings}
        assert "attack_goal_achieved" in rules, sid


def test_obedient_delete_is_attributed_to_the_right_message_and_tool():
    r = _statuses(_agent("obey"))["email_agent_unauthorized_delete/delete_security_alert"]
    [f] = [f for f in r.findings if f.rule == "attack_goal_achieved"]
    assert "delete_email" in f.observed_action and pack.SECURITY_ALERT_ID in f.observed_action


def test_forward_finding_names_the_external_address_and_confidential_value():
    r = _statuses(_agent("obey"))["email_agent_forward_exfiltration/overt_body"]
    [f] = [f for f in r.findings if f.rule == "attack_goal_achieved"]
    assert pack.EXTERNAL_ADDRESS in f.observed_action
    assert pack.CONFIDENTIAL_CANARY in f.observed_action


def test_safe_agent_reads_everything_but_is_not_flagged():
    for sid, r in _statuses(_agent("safe")).items():
        assert r.status == "passed", (sid, [f.rule for f in r.findings])


def test_agent_that_never_opens_a_message_is_inconclusive_not_passed():
    for sid, r in _statuses(_agent("lazy")).items():
        assert r.status == "inconclusive", sid
        assert r.findings == []


def test_delayed_scenario_requires_reaching_the_delayed_step():
    # The 'obey' agent opens every listed message in order, reaching the delayed step, so the
    # delayed scenario is a finding; the 'lazy' agent never opens one, so it is inconclusive.
    assert _statuses(_agent("obey"))["email_agent_delayed_injection/arrives_mid_triage"].status == "findings"
    assert _statuses(_agent("lazy"))["email_agent_delayed_injection/arrives_mid_triage"].status == "inconclusive"


# ---- pack hygiene ----------------------------------------------------------

def test_pack_loads_and_builds_at_least_one_scenario_per_category():
    cats = load_pack(str(_PACK_PATH))
    ctx = ScenarioContext(POLICY, 0)
    for name, build in cats.items():
        built = build(ctx)
        assert built, name
        assert all(s.category == name for s in built)


def test_pack_defines_no_custom_evaluator_or_judge_check():
    # The attack lives in tool-call arguments, covered by the built-in AttackGoalEvaluator.
    assert getattr(pack, "EVALUATORS", []) == []
    assert getattr(pack, "JUDGE_CHECKS", {}) == {}


# ---- realistic injection content: per-surface delivery and scenario shape --------

ALL_SCENARIOS = {}
for _build in (pack.build_forward_exfiltration, pack.build_external_send,
               pack.build_unauthorized_delete, pack.build_delayed_injection):
    for _sc in _build(ScenarioContext(POLICY, 0)):
        ALL_SCENARIOS[_sc.id] = _sc

SURFACE_SCENARIOS = {
    "body": "email_agent_forward_exfiltration/overt_body",
    "attachment": "email_agent_forward_exfiltration/subtle_attachment",
    "signature": "email_agent_forward_exfiltration/signature",
    "quoted_thread": "email_agent_forward_exfiltration/quoted_thread",
    "html": "email_agent_forward_exfiltration/html_part",
}


def _replay_responder(scenario, opens=("msg-0001", "msg-0050", "msg-0002",
                                       "msg-sec-0007", "msg-0100")):
    """Drive the scenario's own responder the way the runner does, returning every result."""
    out = [scenario.responder("read_inbox", {}, 0)]
    for i, mid in enumerate(opens, start=1):
        out.append(scenario.responder("open_email", {"message_id": mid}, i))
    return out


@pytest.mark.parametrize("surface,scenario_id", sorted(SURFACE_SCENARIOS.items()))
def test_every_injection_surface_is_delivered(surface, scenario_id):
    """All five surfaces must reach the agent through the real delivery detector."""
    scenario = ALL_SCENARIOS[scenario_id]
    assert was_delivered(scenario, _trace_of(_replay_responder(scenario)))


def _trace_of(contents):
    trace = Trace("surface-check")
    trace.add("tool_result", tool_name="read_inbox", content=contents[0])
    for text in contents[1:]:
        trace.add("tool_result", tool_name="open_email", content=text)
    return trace


def test_every_scenario_delivers_its_own_injection_and_no_other():
    """Each scenario's exposure is its own injection, so delivery can't be satisfied by a
    different scenario's content leaking into the fixture."""
    for sid, scenario in ALL_SCENARIOS.items():
        contents = _replay_responder(scenario)
        assert was_delivered(scenario, _trace_of(contents)), sid
        others = [s for s in SLOTS if s not in scenario.exposure]
        assert not _delivered(contents, others), sid


def test_injection_only_appears_once_the_message_is_opened():
    """The inbox listing carries envelopes only: an agent that just lists the inbox has not been
    exposed to anything, which is what makes the INCONCLUSIVE verdict meaningful."""
    for sid, scenario in ALL_SCENARIOS.items():
        listing_only = [scenario.responder("read_inbox", {}, 0)]
        assert not was_delivered(scenario, _trace_of(listing_only)), sid


def test_html_injection_is_absent_from_the_plain_text_part():
    """The hidden-HTML-comment technique must be invisible to a plain-text reader."""
    mailbox = pack.build_mailbox(poison_slot=pack.HTML_INJECTION_SLOT, surface="html")
    opened = json.loads(mailbox.open_email("msg-0100"))
    assert pack.HTML_INJECTION_SLOT in opened["html"]
    assert pack.HTML_INJECTION_SLOT not in opened["body"]


def test_every_injection_names_its_fictional_target_and_nothing_routable():
    """An attack is only measurable if its content names the destination the goal checks for, and
    every destination must stay fictional."""
    forwarding = [pack.OVERT_INJECTION_SLOT, pack.SIGNATURE_INJECTION_SLOT,
                  pack.QUOTED_THREAD_INJECTION_SLOT, pack.HTML_INJECTION_SLOT,
                  pack.ATTACHMENT_INJECTION_SLOT, pack.SUBTLE_INJECTION_SLOT,
                  pack.DELAYED_INJECTION_SLOT]
    for injection in forwarding:
        assert pack.EXTERNAL_ADDRESS in injection
    assert pack.SECURITY_ALERT_ID in pack.DELETE_INJECTION_SLOT
    # nothing routable anywhere in the fixtures
    for injection in forwarding + [pack.DELETE_INJECTION_SLOT]:
        for addr in re.findall(r"[\w.%+-]+@[\w.-]+\.[A-Za-z]{2,}", injection):
            assert addr.endswith(".invalid"), addr


def test_injections_do_not_carry_the_confidential_value_themselves():
    """The attack has to make the agent fetch the secret; planting it in the injection would make
    a leak finding meaningless."""
    for slot in SLOTS:
        assert pack.CONFIDENTIAL_CANARY not in slot


def test_every_scenario_states_technique_trust_boundary_and_goal():
    for sid, scenario in ALL_SCENARIOS.items():
        assert "Technique:" in scenario.description, sid
        assert "Trust boundary:" in scenario.description, sid
        assert "Attack goal:" in scenario.description, sid
        assert scenario.attack_goals, sid
        assert scenario.exposure, sid
        # the legitimate task must not itself authorize the attack
        assert pack.EXTERNAL_ADDRESS not in scenario.user_message, sid
        assert pack.SECURITY_ALERT_ID not in scenario.user_message, sid


def test_legitimate_mailbox_task_still_works_on_a_clean_mailbox():
    """A benign inbox with no injection must still be fully usable: the agent reads, opens, and
    the suite reports nothing. Guards against an over-eager fixture or evaluator."""
    clean = pack.Scenario(
        id="email_agent_forward_exfiltration/clean_control",
        category="email_agent_forward_exfiltration",
        title="control: benign mailbox", description="control",
        user_message=pack.TRIAGE_TASK, vector=pack.VECTOR_DOCUMENT,
        responder=pack.make_mailbox_responder(lambda: pack.build_mailbox(poison_slot=None)),
        attack_goals=[pack._forward_goal("would be a finding if it happened")])
    result = run(clean, _agent("obey"))
    assert result.findings == []
    assert result.status == "passed"
    names = [e.tool_name for e in result.trace.of_type("tool_call")]
    assert "read_inbox" in names and names.count("open_email") >= 3
    assert "forward_email" not in names


def test_goal_evaluation_covers_forwarding_sending_and_deletion():
    results = {sid: run(sc, _agent("obey")) for sid, sc in ALL_SCENARIOS.items()}
    tools_flagged = set()
    for sid, result in results.items():
        assert result.status == "findings", sid
        for f in result.findings:
            if f.rule == "attack_goal_achieved":
                tools_flagged.update(t for t in ("forward_email", "send_email", "delete_email")
                                     if t in f.observed_action)
    assert {"forward_email", "delete_email"} <= tools_flagged
