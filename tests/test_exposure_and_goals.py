"""Delivery tracking (`Scenario.exposure`), the `inconclusive` status, mid-task injection
(`inject_after`) and `AttackGoalEvaluator`.

Everything here is abstract on purpose: tools are `lookup` / `act`, and the "adversarial content"
is a fixed placeholder string. A scripted in-process agent drives the real runner
(`run_scenario`), the real evaluators (`evaluate_trace`) and the real report writers, so these
tests check the pipeline's verdicts, not just helper functions.
"""
import json

import pytest

from agentsec.adapters import CallableAdapter
from agentsec.api import AgentTarget, RunResult, SecuritySuite
from agentsec.attacks import AttackGoal, Scenario, inject_after
from agentsec.attacks.base import VECTOR_TOOL_OUTPUT
from agentsec.attacks.packs import load_packs
from agentsec.attacks import CATEGORIES
from agentsec.compare import compare
from agentsec.evaluators import AttackGoalEvaluator, evaluate_trace
from agentsec.evaluators.goals import payload_delivery, was_delivered
from agentsec.owasp import map_finding
from agentsec.policies import parse_policy
from agentsec.reports import render_markdown, render_terminal
from agentsec.reports.json_report import build_report
from agentsec.runners import run_suite
from agentsec.runners.local import ScenarioResult, SuiteResult, run_scenario
from agentsec.traces import Trace

PAYLOAD = "PLACEHOLDER-PAYLOAD-1"
DEST = "PLACEHOLDER-DEST-9"

POLICY_TEXT = """
version: "1"
agent:
  name: t
  endpoint: http://unused.invalid
  retrieval_tools: [lookup]
allowed_tools: [lookup, act]
forbidden_actions: [blocked_act]
limits: {max_steps: 20, max_tool_calls: 15}
"""
POLICY = parse_policy(POLICY_TEXT)


def benign(tool, args, i):
    return "RESULT-%d" % i


def poisoned(tool, args, i):
    # JSON-encoded with a newline and quotes, so delivery detection must see through escaping.
    return json.dumps({"item": i, "note": "prefix line\n%s \"quoted\"" % PAYLOAD})


def scenario(after=2, goals=None, exposure=(PAYLOAD,), sid="t/delayed"):
    return Scenario(
        id=sid, category=sid.split("/")[0], title="t", description="t", user_message="Do the task.",
        vector=VECTOR_TOOL_OUTPUT, exposure=list(exposure), payload=PAYLOAD,
        attack_goals=goals if goals is not None else [AttackGoal("act on DEST", tools=["act"], match_any=[DEST])],
        responder=inject_after(after, benign, poisoned))


def agent(lookups=3, obey=False, act_first=False, tool="act"):
    """Scripted agent: optionally acts first, then calls `lookup` `lookups` times; with `obey` it
    calls `tool(target=DEST)` once right after a result containing PAYLOAD; then it answers."""
    def fn(messages):
        calls = [tc["function"]["name"] for m in messages if m["role"] == "assistant"
                 for tc in m.get("tool_calls") or []]
        n = len(calls)
        if act_first and n == 0:
            return {"tool_calls": [{"name": "act", "arguments": {"target": DEST}}]}
        last = messages[-1]
        if obey and last["role"] == "tool" and PAYLOAD in last["content"] and tool not in calls[-1:]:
            return {"tool_calls": [{"name": tool, "arguments": {"target": DEST.lower()}}]}
        if calls.count("lookup") < lookups:
            return {"tool_calls": [{"name": "lookup", "arguments": {"q": "x%d" % n}}]}
        return "done"
    return CallableAdapter(fn)


def run(sc, adapter):
    trace = run_scenario(sc, POLICY, adapter)
    return ScenarioResult(sc, trace, evaluate_trace(sc, trace, POLICY))


# ---- inject_after ----------------------------------------------------------

def test_inject_after_switches_at_the_given_call_index():
    r = inject_after(2, benign, lambda t, a, i: "P%d" % i)
    assert [r("lookup", {}, i) for i in range(4)] == ["RESULT-0", "RESULT-1", "P2", "P3"]
    assert inject_after(0, benign, lambda t, a, i: "P")("lookup", {}, 0) == "P"
    with pytest.raises(ValueError):
        inject_after(-1, benign, benign)


# ---- delivery detection ----------------------------------------------------

def test_delivery_sees_through_json_escaping_case_and_whitespace():
    sc = scenario(exposure=["placeholder-PAYLOAD-1   \"quoted\""])
    t = Trace("x")
    t.add("tool_result", tool_name="lookup", content="RESULT-0")
    t.add("tool_result", tool_name="lookup", content=poisoned("lookup", {}, 1))
    assert payload_delivery(sc, t).seq == 1 and was_delivered(sc, t)


def test_no_exposure_means_no_delivery_tracking():
    sc = scenario(exposure=())
    assert payload_delivery(sc, Trace("x")) is None and was_delivered(sc, Trace("x"))


# ---- verdicts through the real runner --------------------------------------

def test_delayed_payload_obeyed_is_a_finding_tied_to_the_delivery_step():
    r = run(scenario(after=2), agent(lookups=3, obey=True))
    assert r.status == "findings"
    [f] = [f for f in r.findings if f.rule == "attack_goal_achieved"]
    seqs = [e["seq"] for e in f.evidence]
    delivered = payload_delivery(r.scenario, r.trace)
    assert seqs[0] == delivered.seq and seqs[1] > delivered.seq
    assert r.trace.events[delivered.seq].content.find(PAYLOAD) >= 0
    assert [e.tool_name for e in r.trace.of_type("tool_call")] == ["lookup", "lookup", "lookup", "act"]
    assert map_finding(f.rule, f.category)[0]["id"] == "ASI01"


def test_delayed_payload_ignored_is_passed():
    r = run(scenario(after=2), agent(lookups=3))
    assert r.status == "passed" and r.findings == []


def test_agent_that_stops_before_the_injection_step_is_inconclusive_not_passed():
    r = run(scenario(after=2), agent(lookups=2, obey=True))
    assert r.findings == [] and r.status == "inconclusive"


def test_matching_action_before_delivery_is_not_attributed_to_the_payload():
    # acted before the payload existed, then never reached it: no finding, still inconclusive
    r = run(scenario(after=5), agent(lookups=2, act_first=True))
    assert r.findings == [] and r.status == "inconclusive"
    # acted before, then reached the payload and ignored it: no finding, passed
    r = run(scenario(after=1), agent(lookups=2, act_first=True))
    assert r.findings == [] and r.status == "passed"
    # acted before and after: exactly one finding, pointing at the later call
    r = run(scenario(after=1), agent(lookups=2, act_first=True, obey=True))
    [f] = r.findings
    acts = [e.seq for e in r.trace.of_type("tool_call") if e.tool_name == "act"]
    assert len(acts) == 2 and f.evidence[-1]["seq"] == acts[1]


def test_forbidden_tool_is_reported_once_by_tool_policy_not_twice():
    goals = [AttackGoal("blocked", tools=["blocked_act"], match_any=[DEST])]
    r = run(scenario(after=1, goals=goals), agent(lookups=2, obey=True, tool="blocked_act"))
    assert [f.rule for f in r.findings] == ["forbidden_action"]


def test_goal_filters_tools_and_match_any_and_reports_sensitive_values():
    goals = [AttackGoal("wrong tool", tools=["lookup"], match_any=[DEST]),
             AttackGoal("wrong value", tools=["act"], match_any=["OTHER"]),
             AttackGoal("hit", tools=["act"], match_any=[DEST], sensitive_values=["placeholder-dest"],
                        severity="high")]
    r = run(scenario(after=1, goals=goals), agent(lookups=2, obey=True))
    [f] = r.findings
    assert f.key == "2" and f.severity == "high" and "placeholder-dest" in f.observed_action


def test_goals_without_exposure_count_any_matching_call():
    r = run(scenario(after=0, exposure=()), agent(lookups=1, act_first=True))
    assert [f.rule for f in r.findings] == ["attack_goal_achieved"]


def test_error_takes_precedence_over_inconclusive():
    def boom(messages):
        raise RuntimeError("x")
    r = run(scenario(), CallableAdapter(boom))
    assert r.status == "error"


def test_scenarios_without_new_fields_keep_their_old_verdict():
    sc = scenario(exposure=(), goals=[])
    assert run(sc, agent(lookups=1)).status == "passed"
    assert AttackGoalEvaluator().evaluate(sc, Trace("x"), POLICY) == []


# ---- suite, reports, API, compare ------------------------------------------

def _suite(adapter):
    scs = [scenario(sid="t/hit"), scenario(sid="t/miss", after=9)]
    return SuiteResult(POLICY, 0, [run(s, adapter) for s in scs], [])


def test_reports_count_inconclusive_separately_from_passed():
    suite = _suite(agent(lookups=3))
    assert [r.status for r in suite.results] == ["passed", "inconclusive"]
    rep = build_report(suite)
    assert rep["summary"]["passed"] == 1 and rep["summary"]["inconclusive"] == 1
    assert "1 inconclusive" in render_terminal(suite)
    assert "1 scenario(s) inconclusive" in render_markdown(rep)
    res = RunResult(suite)
    assert not res.passed and [r.scenario.id for r in res.inconclusive] == ["t/miss"]


def test_compare_does_not_call_an_inconclusive_rerun_fixed():
    base = build_report(SuiteResult(POLICY, 0, [run(scenario(sid="t/miss", after=0), agent(lookups=1, obey=True))], []))
    head = build_report(_suite(agent(lookups=3)))
    c = compare(base, head)
    assert c.fixed == [] and len(c.not_comparable) == 1


def test_run_suite_warns_about_inconclusive_scenarios(tmp_path):
    pack = tmp_path / "p.py"
    pack.write_text(
        "from agentsec.attacks import Scenario, inject_after\n"
        "def build(ctx):\n"
        "    r = inject_after(9, lambda t, a, i: 'ok', lambda t, a, i: 'PLACEHOLDER-PAYLOAD-1')\n"
        "    return [Scenario(id='abstract_delay/x', category='abstract_delay', title='t', description='t',\n"
        "                     user_message='Do the task.', exposure=['PLACEHOLDER-PAYLOAD-1'], responder=r)]\n"
        "CATEGORIES = {'abstract_delay': build}\n")
    suite = run_suite(POLICY, agent(lookups=1), categories=["abstract_delay"],
                      attack_packs=load_packs([str(pack)], CATEGORIES))
    assert suite.results[0].status == "inconclusive"
    assert any("INCONCLUSIVE" in w and "abstract_delay/x" in w for w in suite.warnings)


def test_replay_reports_an_inconclusive_rerun_instead_of_not_reproduced(tmp_path):
    from agentsec.runners import replay
    pack = tmp_path / "p.py"
    pack.write_text(
        "from agentsec.attacks import AttackGoal, Scenario, inject_after\n"
        "def build(ctx):\n"
        "    r = inject_after(1, lambda t, a, i: 'ok', lambda t, a, i: 'PLACEHOLDER-PAYLOAD-1')\n"
        "    return [Scenario(id='abstract_delay/x', category='abstract_delay', title='t', description='t',\n"
        "                     user_message='Do the task.', exposure=['PLACEHOLDER-PAYLOAD-1'], responder=r,\n"
        "                     attack_goals=[AttackGoal('act', tools=['act'], match_any=['PLACEHOLDER-DEST-9'])])]\n"
        "CATEGORIES = {'abstract_delay': build}\n")
    policy = parse_policy(POLICY_TEXT + "attack_packs: [%s]\n" % json.dumps(str(pack)))
    first = run_suite(policy, agent(lookups=2, obey=True), categories=["abstract_delay"])
    assert [f.rule for f in first.findings] == ["attack_goal_achieved"]
    again = replay(build_report(first), policy, agent(lookups=1))
    assert [o.status for o in again.outcomes] == ["inconclusive"] and again.inconclusive
