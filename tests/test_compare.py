import json

import pytest

from agentsec.cli.main import main
from agentsec.compare import CompareError, compare, load


def finding(sc, rule, sev="high"):
    return {"id": "%s:%s" % (sc, rule), "rule": rule, "scenario_id": sc, "severity": sev,
            "title": "%s %s" % (sc, rule)}


def report(findings, scenarios, seed=0, statuses=None):
    statuses = statuses or {}
    return {"run_config": {"seed": seed, "policy": {"a": 1}},
            "findings": findings,
            "scenarios": [{"id": s, "status": statuses.get(s, "passed")} for s in scenarios]}


def test_new_fixed_unchanged():
    base = report([finding("a", "r"), finding("b", "r")], ["a", "b", "c"])
    head = report([finding("b", "r"), finding("c", "r", "critical")], ["a", "b", "c"])
    c = compare(base, head)
    assert [f["id"] for f in c.new] == ["c:r"]
    assert [f["id"] for f in c.fixed] == ["a:r"]
    assert [f["id"] for f in c.unchanged] == ["b:r"]
    assert not c.warnings


def test_severity_change():
    c = compare(report([finding("a", "r", "medium"), finding("b", "r", "high")], ["a", "b"]),
                report([finding("a", "r", "critical"), finding("b", "r", "low")], ["a", "b"]))
    assert [f["id"] for f in c.worse] == ["a:r"] and [f["id"] for f in c.better] == ["b:r"]
    assert [f["id"] for f in c.regressions()] == ["a:r"]
    assert c.regressions("critical")[0]["id"] == "a:r"


def test_missing_or_errored_scenario_is_not_fixed():
    base = report([finding("a", "r"), finding("b", "r")], ["a", "b"])
    head = report([], ["b"], statuses={"b": "error"})
    c = compare(base, head)
    assert not c.fixed and len(c.not_comparable) == 2
    assert any("only in the baseline" in w for w in c.warnings)


def test_warns_on_seed_and_policy_difference():
    head = report([], ["a"], seed=1)
    head["run_config"]["policy"] = {"a": 2}
    c = compare(report([], ["a"]), head)
    assert any("seeds differ" in w for w in c.warnings) and any("policy differs" in w for w in c.warnings)


def test_load_errors(tmp_path):
    with pytest.raises(CompareError):
        load(str(tmp_path / "nope.json"))
    bad = tmp_path / "x.json"
    bad.write_text("{}")
    with pytest.raises(CompareError):
        load(str(bad))


def write(tmp_path, name, rep):
    p = tmp_path / name
    p.write_text(json.dumps(rep))
    return str(p)


def test_cli_exit_codes(tmp_path, capsys):
    base = write(tmp_path, "b.json", report([finding("a", "r")], ["a", "b"]))
    clean = write(tmp_path, "c.json", report([finding("a", "r")], ["a", "b"]))
    worse = write(tmp_path, "w.json", report([finding("a", "r"), finding("b", "r", "medium")], ["a", "b"]))
    assert main(["compare", base, clean]) == 0
    assert main(["compare", base, worse]) == 1
    assert main(["compare", base, worse, "--fail-on", "high"]) == 0
    assert main(["compare", base, worse, "--fail-on", "none"]) == 0
    assert "NEW findings" in capsys.readouterr().out
    assert main(["compare", base, str(tmp_path / "missing.json")]) == 2
