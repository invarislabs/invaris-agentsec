"""The local dashboard shows AgentSec 0.8.0 verdicts the same way `agentsec compare` and the hosted dashboard
do: inconclusive is never passed or fixed, attack timelines come from the report, and what the agent reported
about itself is shown. Scripted in-process agents drive the real pipeline; nothing here is a model's behaviour."""
import json

from agentsec import verdicts
from agentsec.adapters import CallableAdapter
from agentsec.attacks import CATEGORIES
from agentsec.attacks.packs import load_packs
from agentsec.compare import compare
from agentsec.dashboard import ReportIndex, compare_reports, insights
from agentsec.dashboard.server import STATIC_DIR
from agentsec.reports.json_report import build_report
from agentsec.runners import run_suite

from test_email_attack_pack import POLICY, _PACK_PATH, _agent


def _write(tmp_path, name, mode, describe=False):
    inner = _agent(mode).fn

    def fn(messages, tools):
        out = inner(messages, tools)
        out = {"content": out} if isinstance(out, str) else dict(out)
        if describe:
            out["agent"] = {"name": "email-assistant", "backend": "scripted", "configuration": mode}
        return out
    suite = run_suite(POLICY, CallableAdapter(fn), attack_packs=load_packs([str(_PACK_PATH)], CATEGORIES))
    d = tmp_path / name
    d.mkdir()
    path = d / "report.json"
    path.write_text(json.dumps(build_report(suite, "examples/attack_packs/email_assistant.agentsec.yaml")))
    return json.loads(path.read_text()), path


def test_run_list_counts_inconclusive_and_never_all_passed(tmp_path):
    _write(tmp_path, "lazy", "lazy")
    [entry] = ReportIndex([str(tmp_path)]).scan()
    assert entry.meta["inconclusive"] == entry.meta["scenarios"] and entry.meta["passed"] == 0


def test_insights_carry_evaluation_timelines_and_reported_agent(tmp_path):
    rep, _ = _write(tmp_path, "obey", "obey", describe=True)
    ins = insights(rep)
    assert ins["evaluation"] == verdicts.evaluation(rep) and ins["evaluation"]["finding_rate"] == 1.0
    assert ins["attack_goals"] == verdicts.attack_goals(rep) and ins["attack_goals"]
    assert ins["reported"] == [{"name": "email-assistant", "backend": "scripted", "configuration": "obey"}]
    assert ins["pack_categories"] == sorted({s["category"] for s in rep["scenarios"]})
    lazy, _ = _write(tmp_path, "lazy", "lazy")
    li = insights(lazy)
    assert all(c["by_status"]["inconclusive"] == c["scenarios"] and c["by_status"]["passed"] == 0
               for c in li["categories"])
    assert li["vectors"][0]["inconclusive"] == len(lazy["scenarios"])


def test_dashboard_compare_matches_agentsec_compare(tmp_path):
    base, _ = _write(tmp_path, "obey", "obey")
    head, _ = _write(tmp_path, "lazy", "lazy")
    c, cli = compare_reports(base, head), compare(base, head)
    assert not c["fixed"] and not cli.fixed
    assert sorted(f["id"] for f in c["not_comparable"]) == sorted(f["id"] for f in cli.not_comparable)
    assert {f["reason"] for f in c["not_comparable"]} == {"inconclusive"}
    assert c["verdict_changes"] == cli.verdict_changes == verdicts.verdict_changes(base, head)
    assert c["evaluation"] == {"base": cli.base_evaluation, "head": cli.head_evaluation}


def test_older_reports_still_load(tmp_path):
    old = {"findings": [], "scenarios": [{"id": "x/y", "category": "x", "status": "passed", "finding_ids": [],
                                          "trace": {"events": []}}],
           "summary": {"scenarios": 1, "passed": 1, "findings": 0}, "run_config": {"seed": 0}}
    (tmp_path / "report.json").write_text(json.dumps(old))
    [entry] = ReportIndex([str(tmp_path)]).scan()
    assert entry.error is None and entry.meta["inconclusive"] == 0
    ins = insights(old)
    assert ins["attack_goals"] == [] and ins["reported"] == [] and ins["evaluation"]["tested"] == 1
    assert compare_reports(old, old)["verdict_changes"] == []


def test_page_knows_every_verdict():
    with open(STATIC_DIR + "/app.js", encoding="utf-8") as fh:
        js = fh.read()
    for status in verdicts.STATUSES:
        assert status in js
    assert "Inconclusive" in js and "attackTimeline" in js and "verdictComparison" in js and "Scripted stand-in" in js
