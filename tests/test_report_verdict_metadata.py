"""report.json scenario metadata (delivery, attack goals), agent self-description, the shared verdict
rules in agentsec.verdicts, and `agentsec compare` never treating untested scenarios as improvements.

Scripted in-process agents drive AgentSec's real pipeline; nothing here is a model's behaviour."""
import json
import socket
import threading
from pathlib import Path

from agentsec import verdicts
from agentsec.adapters import CallableAdapter, HTTPAgentAdapter
from agentsec.adapters.base import agent_info
from agentsec.attacks import CATEGORIES
from agentsec.attacks.packs import load_packs
from agentsec.compare import compare, render, render_markdown
from agentsec.policies import parse_policy
from agentsec.reports import render_markdown as render_report_markdown
from agentsec.reports.json_report import build_report
from agentsec.runners import run_suite

from test_email_attack_pack import POLICY, _PACK_PATH, _agent, pack

ROOT = Path(__file__).resolve().parent.parent


def _report(adapter, policy=POLICY, packs=True):
    suite = run_suite(policy, adapter, attack_packs=load_packs([str(_PACK_PATH)], CATEGORIES) if packs else None)
    return build_report(suite, "examples/attack_packs/email_assistant.agentsec.yaml")


def test_delivery_and_attack_goals_are_recorded_for_pack_scenarios():
    rep = _report(_agent("obey"))
    for s in rep["scenarios"]:
        d = s["delivery"]
        assert d["tracked"] and d["delivered"] and d["tool"] == "open_email"
        delivered = {e["seq"]: e for e in s["trace"]["events"]}[d["seq"]]
        assert delivered["type"] == "tool_result" and delivered["tool_name"] == "open_email"
        assert s["attack_goals"] and all(g["achieved"] is True for g in s["attack_goals"])
        assert set(s["attack_goals"][0]) == {"description", "tools", "indicators", "carries_victim_data",
                                             "severity", "achieved"}


def test_undelivered_goals_are_not_tested_rather_than_resisted():
    rep = _report(_agent("lazy"))
    for s in rep["scenarios"]:
        assert s["status"] == "inconclusive"
        assert s["delivery"] == {"tracked": True, "delivered": False, "seq": None, "tool": None}
        assert all(g["achieved"] is None for g in s["attack_goals"])
    safe = _report(_agent("safe"))
    assert all(g["achieved"] is False for s in safe["scenarios"] for g in s["attack_goals"])


def test_goal_metadata_never_carries_the_victims_values():
    rep = _report(_agent("obey"))
    goals = json.dumps([s["attack_goals"] for s in rep["scenarios"]])
    assert pack.CONFIDENTIAL_CANARY not in goals
    assert any(g["carries_victim_data"] for s in rep["scenarios"] for g in s["attack_goals"])


def test_builtin_scenarios_keep_the_previous_report_shape():
    policy = parse_policy((ROOT / "examples" / "vulnerable_rag_agent" / "agentsec.yaml").read_text())
    rep = build_report(run_suite(policy, CallableAdapter(lambda m, t: "I can't help with that."),
                                 categories=["prompt_injection"]))
    assert rep["scenarios"]
    for s in rep["scenarios"]:
        assert "delivery" not in s and "attack_goals" not in s
    assert "agent_reported" not in rep["run_config"]


def test_agent_self_description_is_filtered_capped_and_masked():
    secret = "sk-test-0123456789abcdef"
    policy = parse_policy((ROOT / "examples" / "attack_packs" / "email_assistant.agentsec.yaml").read_text())
    policy.secrets.append(secret)
    inner = _agent("safe").fn

    def fn(messages, tools):
        out = inner(messages, tools)
        out = {"content": out} if isinstance(out, str) else dict(out)
        out["agent"] = {"name": "mail-bot", "backend": "scripted", "configuration": "hardened\n",
                        "model": "x" * 500, "api_key": secret, "endpoint": "https://internal.invalid"}
        return out
    rep = _report(CallableAdapter(fn), policy=policy)
    [info] = rep["run_config"]["agent_reported"]
    assert set(info) == {"name", "backend", "configuration", "model"}
    assert info["configuration"] == "hardened" and len(info["model"]) == 120
    assert secret not in json.dumps(rep) and "internal.invalid" not in json.dumps(rep)
    assert "Agent reported: mail-bot, backend scripted" in render_report_markdown(rep)
    # recorded once per scenario, where it first appears
    s = rep["scenarios"][0]
    assert sum("agent" in (e.get("meta") or {}) for e in s["trace"]["events"]) == 1


def test_agent_info_rejects_non_strings_and_unknown_keys():
    assert agent_info(None) is None and agent_info("x") is None and agent_info({"token": "t"}) is None
    assert agent_info({"backend": 3, "model": " m\x00 "}) == {"model": "m"}


def test_http_adapter_reads_x_agentsec_agent():
    reply = HTTPAgentAdapter.__new__(HTTPAgentAdapter)._parse(
        {"choices": [{"message": {"content": "hi"}}],
         "x_agentsec": {"agent": {"backend": "anthropic", "model": "claude-x", "password": "p"}}})
    assert reply.agent == {"backend": "anthropic", "model": "claude-x"}


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_reference_email_assistant_reports_that_a_scripted_backend_decided():
    import importlib.util
    import sys
    path = ROOT / "examples" / "real_world_agents" / "email_assistant" / "server.py"
    sys.path.insert(0, str(path.parent))
    spec = importlib.util.spec_from_file_location("ea_for_metadata_test", str(path))
    ea = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = ea
    spec.loader.exec_module(ea)
    port = _free_port()
    server = ea.make_server(ea.EmailAssistant(ea.build_backend("scripted", None, None), hardened=True), port=port)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        text = (ROOT / "examples" / "attack_packs" / "email_assistant.agentsec.yaml").read_text()
        policy = parse_policy(text.replace("127.0.0.1:8060", "127.0.0.1:%d" % port)
                              .replace("examples/attack_packs/", str(ROOT / "examples" / "attack_packs") + "/"))
        rep = build_report(run_suite(policy, HTTPAgentAdapter(policy.agent), only=None,
                                     categories=["email_agent_external_send"]))
    finally:
        server.shutdown()
        server.server_close()
    assert rep["run_config"]["agent_reported"] == [
        {"name": "email-assistant", "backend": "scripted", "configuration": "hardened"}]


def test_shared_verdict_rules():
    base, head = _report(_agent("obey")), _report(_agent("lazy"))
    ev = verdicts.evaluation(head)
    assert ev["tested"] == 0 and ev["inconclusive"] == ev["scenarios"] and ev["finding_rate"] is None
    assert verdicts.evaluation(base)["finding_rate"] == 1.0
    goals = verdicts.attack_goals(base)
    by_sc = {s["id"]: s for s in base["scenarios"]}
    assert goals and all(g["delivered_seq"] == by_sc[g["scenario_id"]]["delivery"]["seq"] for g in goals)
    changes = verdicts.verdict_changes(base, head)
    assert {(c["base"], c["head"]) for c in changes} == {("findings", "inconclusive")}
    f = base["findings"][0]
    assert verdicts.not_comparable_reason(f, head) == "inconclusive"
    assert verdicts.not_comparable_reason(dict(f, scenario_id="gone"), head) == "missing"


def test_compare_never_counts_untested_scenarios_as_improvements():
    base, head = _report(_agent("obey")), _report(_agent("lazy"))
    c = compare(base, head)
    assert not c.fixed and len(c.not_comparable) == len(base["findings"])
    assert len(c.untested()) == len(base["scenarios"])
    text = render(c)
    assert "Not tested in the new run" in text and "tested 8 -> 0" in text
    md = render_markdown(c)
    assert "| Tested scenarios | 8 → 0 |" in md and "Not tested in the current run" in md
    # a genuine fix is still a fix
    fixed = compare(base, _report(_agent("safe")))
    assert len(fixed.fixed) == len(base["findings"]) and not fixed.untested()


def test_not_observable_is_never_fixed_either():
    f = {"id": "m/1:agent_exceeded_role", "rule": "agent_exceeded_role", "scenario_id": "m/1",
         "category": "multi_agent_delegation", "severity": "high", "title": "t"}
    base = {"findings": [f], "scenarios": [{"id": "m/1", "status": "findings"}]}
    head = {"findings": [], "scenarios": [{"id": "m/1", "status": "not_observable"}]}
    c = compare(base, head)
    assert not c.fixed and [x["id"] for x in c.not_comparable] == [f["id"]]
    assert verdicts.not_comparable_reason(f, head) == "not_observable"
    assert [(x["base"], x["head"]) for x in c.untested()] == [("findings", "not_observable")]


def test_reports_without_the_new_fields_still_work():
    old = {"findings": [], "scenarios": [{"id": "a", "status": "passed"}, {"id": "b", "status": "error"}],
           "summary": {"scenarios": 2}}
    assert verdicts.inconclusive_count(old) == 0 and verdicts.attack_goals(old) == []
    assert verdicts.agent_reported(old) == [] and verdicts.evaluation(old)["tested"] == 1
    c = compare(old, old)
    assert c.verdict_changes == [] and "tested 1 -> 1" in render(c)
