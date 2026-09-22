import json

import pytest

from agentsec.adapters import HTTPAgentAdapter
from agentsec.policies import parse_policy
from agentsec.reports import build_report, build_sarif, render_sarif, write_reports
from agentsec.runners import run_suite

SECRET = "sk-live-INVARIS-DEMO-7f3a9c1e5b2d"


@pytest.fixture(scope="module")
def report(vulnerable_url):
    from conftest import POLICY_YAML
    policy = parse_policy(POLICY_YAML.format(endpoint=vulnerable_url))
    return build_report(run_suite(policy, HTTPAgentAdapter(policy.agent)))


def test_sarif_is_valid_json_with_expected_shape(report):
    log = build_sarif(report)
    assert log["version"] == "2.1.0"
    assert log["$schema"].endswith("sarif-schema-2.1.0.json")
    run = log["runs"][0]
    assert run["tool"]["driver"]["name"] == "invaris-agentsec"
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    result_rule_ids = {r["ruleId"] for r in run["results"]}
    # Every result references a rule that was declared, and vice versa.
    assert result_rule_ids == rule_ids
    assert len(run["results"]) == len(report["findings"])


def test_sarif_levels_and_fingerprints(report):
    log = build_sarif(report)
    results = log["runs"][0]["results"]
    findings_by_id = {f["id"]: f for f in report["findings"]}
    for r in results:
        f = findings_by_id[r["partialFingerprints"]["agentsecFindingId"]]
        assert r["level"] in ("error", "warning", "note")
        if f["severity"] in ("critical", "high"):
            assert r["level"] == "error"
        elif f["severity"] == "medium":
            assert r["level"] == "warning"
        else:
            assert r["level"] == "note"
        assert r["properties"]["scenarioId"] == f["scenario_id"]


def test_sarif_masks_secrets_like_other_formats(report):
    text = render_sarif(report)
    assert SECRET not in text
    json.loads(text)  # render_sarif must produce parseable JSON


def test_build_report_threads_policy_path_into_sarif_and_replay(vulnerable_url):
    from conftest import POLICY_YAML
    policy = parse_policy(POLICY_YAML.format(endpoint=vulnerable_url))
    suite = run_suite(policy, HTTPAgentAdapter(policy.agent))
    real_path = "examples/vulnerable_rag_agent/agentsec.yaml"
    report_with_path = build_report(suite, policy_path=real_path)
    assert report_with_path["run_config"]["policy_path"] == real_path
    assert "--policy %s" % real_path in report_with_path["run_config"]["replay"]

    log = build_sarif(report_with_path)
    uris = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            for r in log["runs"][0]["results"]}
    assert uris == {real_path}


def test_sarif_falls_back_to_placeholder_without_a_policy_path(report):
    # `report` fixture is built via build_report(suite) with no policy_path (backward compatible).
    assert report["run_config"].get("policy_path") is None
    log = build_sarif(report)
    for r in log["runs"][0]["results"]:
        assert r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "agentsec.yaml"


def test_sarif_with_no_findings_is_still_valid():
    empty_report = {
        "tool": {"version": "0"}, "run_config": {}, "findings": [],
    }
    log = build_sarif(empty_report)
    assert log["runs"][0]["results"] == []
    assert log["runs"][0]["tool"]["driver"]["rules"] == []


def test_write_reports_writes_sarif(tmp_path, report):
    # write_reports operates on a SuiteResult, not a report dict; rebuild one here.
    from agentsec.reports import write_reports as _write
    # Reuse the already-computed report to avoid re-running the suite: monkeypatch build_report.
    import agentsec.reports.writers as writers_mod

    class _FakeSuite:
        pass

    orig_build_report = writers_mod.build_report
    writers_mod.build_report = lambda suite, policy_path=None: report
    try:
        _, paths = _write(_FakeSuite(), str(tmp_path), ["sarif"])
    finally:
        writers_mod.build_report = orig_build_report
    assert len(paths) == 1
    assert paths[0].endswith("results.sarif")
    with open(paths[0]) as fh:
        log = json.load(fh)
    assert log["version"] == "2.1.0"
