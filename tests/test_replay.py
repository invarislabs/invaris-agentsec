import json

import pytest

from agentsec.adapters import HTTPAgentAdapter
from agentsec.cli.main import main
from agentsec.policies import parse_policy
from agentsec.reports import write_reports
from agentsec.runners import ReplayError, load_report, replay, run_suite


def make_report(policy_text, url, tmp_path, tests="tests: [prompt_injection, memory_poisoning]\n", seed=3):
    policy = parse_policy(policy_text.format(endpoint=url) + tests)
    suite = run_suite(policy, HTTPAgentAdapter(policy.agent), seed=seed)
    _, paths = write_reports(suite, str(tmp_path / "orig"), ["json"])
    return policy, paths[0]


def test_replay_reproduces_same_findings_against_same_agent(policy_text, vulnerable_url, tmp_path):
    policy, path = make_report(policy_text, vulnerable_url, tmp_path)
    report = load_report(path)
    res = replay(report, policy, HTTPAgentAdapter(policy.agent))
    assert res.seed == 3 and res.outcomes
    assert {o.status for o in res.outcomes} == {"reproduced"}
    assert res.new_findings == [] and not res.policy_changed


def test_replay_reports_fixed_when_agent_is_hardened(policy_text, vulnerable_url, safe_url, tmp_path):
    _, path = make_report(policy_text, vulnerable_url, tmp_path)
    fixed_policy = parse_policy(policy_text.format(endpoint=safe_url) + "tests: [prompt_injection]\n")
    res = replay(load_report(path), fixed_policy, HTTPAgentAdapter(fixed_policy.agent))
    assert {o.status for o in res.outcomes} == {"not_reproduced"}
    assert res.policy_changed  # policy text differs from the report's


def test_replay_single_finding_and_scenario_filters(policy_text, vulnerable_url, tmp_path):
    policy, path = make_report(policy_text, vulnerable_url, tmp_path)
    report = load_report(path)
    fid = report["findings"][0]["id"]
    res = replay(report, policy, HTTPAgentAdapter(policy.agent), finding_ids=[fid])
    assert [o.finding_id for o in res.outcomes] == [fid]
    assert len(res.suite.results) == 1
    sid = "memory_poisoning/doc_instruction_marker"
    res = replay(report, policy, HTTPAgentAdapter(policy.agent), scenario_ids=[sid])
    assert {o.scenario_id for o in res.outcomes} == {sid}
    assert len(res.outcomes) == 2  # injection_followed + memory_poisoned


def test_replay_uses_the_recorded_seed(policy_text, vulnerable_url, tmp_path):
    policy, path = make_report(policy_text, vulnerable_url, tmp_path, seed=11)
    report = load_report(path)
    res = replay(report, policy, HTTPAgentAdapter(policy.agent))
    orig = {s["id"]: s["trace"]["events"][0]["content"] for s in report["scenarios"]}
    for r in res.suite.results:
        assert r.trace.events[0].content == orig[r.scenario.id]


def test_replay_errors(policy_text, vulnerable_url, tmp_path):
    policy, path = make_report(policy_text, vulnerable_url, tmp_path)
    report = load_report(path)
    with pytest.raises(ReplayError, match="not in the report"):
        replay(report, policy, HTTPAgentAdapter(policy.agent), finding_ids=["nope"])
    with pytest.raises(ReplayError, match="not in the report"):
        replay(report, policy, HTTPAgentAdapter(policy.agent), scenario_ids=["x/y"])
    bad = tmp_path / "bad.json"
    bad.write_text("{}")
    with pytest.raises(ReplayError, match="does not look like"):
        load_report(str(bad))
    with pytest.raises(ReplayError, match="cannot read"):
        load_report(str(tmp_path / "missing.json"))


def test_cli_replay_exit_codes(policy_text, vulnerable_url, safe_url, tmp_path, capsys):
    _, path = make_report(policy_text, vulnerable_url, tmp_path)
    vuln = tmp_path / "vuln.yaml"
    vuln.write_text(policy_text.format(endpoint=vulnerable_url) + "tests: [prompt_injection, memory_poisoning]\n")
    out = str(tmp_path / "r")
    assert main(["replay", path, "-p", str(vuln), "-o", out]) == 1
    text = capsys.readouterr().out
    assert "REPRODUCED" in text and "reproduced," in text
    assert (tmp_path / "r" / "report.json").exists()

    safe = tmp_path / "safe.yaml"
    safe.write_text(policy_text.format(endpoint=safe_url) + "tests: [prompt_injection, memory_poisoning]\n")
    assert main(["replay", path, "-p", str(safe), "-o", out]) == 0
    assert "NOT REPRODUCED" in capsys.readouterr().out

    down = tmp_path / "down.yaml"
    down.write_text(policy_text.format(endpoint="http://127.0.0.1:1/agent") + "tests: [prompt_injection]\n")
    assert main(["replay", path, "-p", str(down), "-o", out]) == 2
    assert main(["replay", str(tmp_path / "nope.json"), "-p", str(safe)]) == 2
