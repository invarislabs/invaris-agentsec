import json

import jsonschema
import pytest

from agentsec.adapters import HTTPAgentAdapter
from agentsec.attacks import CATEGORIES
from agentsec.cli.main import main
from agentsec.policies import parse_policy
from agentsec.reports import build_report, render_terminal
from agentsec.runners import run_suite
from agentsec.traces import trace_json_schema

SECRET = "sk-live-INVARIS-DEMO-7f3a9c1e5b2d"


def suite_for(policy_text, url, **kw):
    policy = parse_policy(policy_text.format(endpoint=url))
    return run_suite(policy, HTTPAgentAdapter(policy.agent), **kw)


def test_vulnerable_agent_has_findings_in_every_category(policy_text, vulnerable_url):
    suite = suite_for(policy_text, vulnerable_url)
    assert {f.category for f in suite.findings} == set(CATEGORIES)
    assert not [r for r in suite.results if r.status == "error"]
    sev = {f.severity for f in suite.findings}
    assert {"critical", "high", "medium"} <= sev


def test_safe_agent_passes_everything(policy_text, safe_url):
    suite = suite_for(policy_text, safe_url)
    assert len(suite.results) == 30
    assert suite.findings == []


def test_runs_are_reproducible_for_a_seed(policy_text, vulnerable_url):
    def digest(seed):
        rep = build_report(suite_for(policy_text, vulnerable_url, seed=seed))
        return json.dumps([(s["id"], [e["content"] for e in s["trace"]["events"] if e["type"] == "user_message"],
                            s["finding_ids"]) for s in rep["scenarios"]], sort_keys=True)
    assert digest(7) == digest(7)
    assert digest(7) != digest(8)  # markers/canaries change with the seed


def test_report_is_valid_and_masks_secrets(policy_text, vulnerable_url):
    suite = suite_for(policy_text, vulnerable_url)
    report = build_report(suite)
    text = json.dumps(report, ensure_ascii=False)
    assert SECRET not in text and "sk-l…2d [REDACTED]" in text
    assert report["run_config"]["policy"]["secrets_count"] == 1
    assert report["summary"]["findings"] == len(report["findings"]) > 0
    for sc in report["scenarios"]:
        jsonschema.validate(sc["trace"], trace_json_schema())
    f = report["findings"][0]
    assert {"input", "evidence", "policy_violated", "observed_action", "remediation"} <= set(f)


def test_terminal_report_shape(policy_text, vulnerable_url):
    out = render_terminal(suite_for(policy_text, vulnerable_url), report_path=".agentsec/report.json")
    lines = out.splitlines()
    assert lines[0] == "Invaris AgentSec"
    assert "30 scenarios executed" in out and "0 passed" in out
    assert out.index("CRITICAL") < out.index("HIGH") < out.index("MEDIUM")
    assert SECRET not in out
    assert lines[-1] == "Report written to .agentsec/report.json"


def test_memory_poisoning_is_skipped_with_warning(policy_text, safe_url):
    suite = suite_for(policy_text + "tests: [prompt_injection, memory_poisoning]\n", safe_url)
    assert len(suite.results) == 5
    assert "memory_poisoning is planned for Phase 2" in suite.warnings[0]


def write_policy(tmp_path, text, url):
    path = tmp_path / "agentsec.yaml"
    path.write_text(text.format(endpoint=url))
    return str(path)


def test_cli_exit_codes(tmp_path, policy_text, vulnerable_url, safe_url, capsys):
    out = str(tmp_path / "out")
    assert main(["test", "-p", write_policy(tmp_path, policy_text, vulnerable_url), "-o", out]) == 1
    assert (tmp_path / "out" / "report.json").exists()
    assert main(["test", "-p", write_policy(tmp_path, policy_text, vulnerable_url), "-o", out,
                 "--fail-on", "none"]) == 0
    # only medium findings exist in this category, so --fail-on high passes
    assert main(["test", "-p", write_policy(tmp_path, policy_text, vulnerable_url), "-o", out,
                 "-s", "loop_and_budget_limits", "--fail-on", "high"]) == 0
    assert main(["test", "-p", write_policy(tmp_path, policy_text, safe_url), "-o", out]) == 0
    capsys.readouterr()


def test_cli_scenario_filter_and_errors(tmp_path, policy_text, safe_url, capsys):
    pol = write_policy(tmp_path, policy_text, safe_url)
    assert main(["test", "-p", pol, "-o", str(tmp_path / "o"), "-s", "prompt_injection/ignore_previous"]) == 0
    assert "1 scenarios executed" in capsys.readouterr().out
    assert main(["test", "-p", pol, "-o", str(tmp_path / "o"), "-s", "nope"]) == 2
    assert main(["test", "-p", str(tmp_path / "missing.yaml")]) == 2
    bad = write_policy(tmp_path, policy_text + "tests: [bogus]\n", safe_url)
    assert main(["test", "-p", bad, "-o", str(tmp_path / "o")]) == 2
    assert "unknown test category" in capsys.readouterr().err


def test_cli_unreachable_agent_is_exit_2(tmp_path, policy_text, capsys):
    pol = write_policy(tmp_path, policy_text, "http://127.0.0.1:1/agent")
    assert main(["test", "-p", pol, "-o", str(tmp_path / "o")]) == 2
    assert "Every scenario errored" in capsys.readouterr().err


def test_cli_init_and_schema(tmp_path, capsys):
    target = str(tmp_path / "agentsec.yaml")
    assert main(["init", target]) == 0
    assert main(["init", target]) == 2  # never overwrites
    parse_policy(open(target).read())
    assert main(["schema", "policy"]) == 0
    assert '"AgentSec policy' in capsys.readouterr().out
