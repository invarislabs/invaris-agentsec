import json
from html.parser import HTMLParser

import pytest

from agentsec.adapters import HTTPAgentAdapter
from agentsec.cli.main import main
from agentsec.owasp import ASI, map_finding
from agentsec.policies import parse_policy
from agentsec.reports import (annotations, build_report, render_html, render_markdown, write_reports)
from agentsec.reports.github import _escape_data
from agentsec.runners import run_suite

SECRET = "sk-live-INVARIS-DEMO-7f3a9c1e5b2d"


@pytest.fixture(scope="module")
def report(vulnerable_url):
    from conftest import POLICY_YAML
    policy = parse_policy(POLICY_YAML.format(endpoint=vulnerable_url))
    return build_report(run_suite(policy, HTTPAgentAdapter(policy.agent)))


def test_owasp_mapping_basics():
    assert [o["id"] for o in map_finding("injection_followed", "prompt_injection")] == ["ASI01"]
    assert [o["id"] for o in map_finding("memory_poisoned", "memory_poisoning")] == ["ASI06", "ASI01"]
    assert [o["id"] for o in map_finding("forbidden_action", "loop_and_budget_limits")] == ["ASI02"]
    ids = [o["id"] for o in map_finding("forbidden_action", "indirect_prompt_injection")]
    assert ids == ["ASI02", "ASI01"]
    assert [o["id"] for o in map_finding("secret_leak", "memory_poisoning")] == ["ASI06", "ASI03"]
    assert map_finding("something_new", "x") == []
    assert set(ASI) == {"ASI%02d" % i for i in range(1, 11)}


def test_every_finding_rule_is_mapped(report):
    unmapped = [f["rule"] for f in report["findings"] if not f["owasp"]]
    assert unmapped == []
    assert report["summary"]["by_owasp"]["ASI01"] > 0
    assert report["owasp_framework"]["categories"]["ASI06"] == "Memory & Context Poisoning"


class _Balanced(HTMLParser):
    VOID = {"meta", "br", "hr", "img", "input", "link"}

    def __init__(self):
        super().__init__()
        self.stack, self.problems = [], []

    def handle_starttag(self, tag, attrs):
        if tag not in self.VOID:
            self.stack.append(tag)

    def handle_endtag(self, tag):
        if not self.stack or self.stack.pop() != tag:
            self.problems.append(tag)


def test_html_report_is_well_formed_self_contained_and_masked(report):
    page = render_html(report)
    p = _Balanced()
    p.feed(page)
    assert p.problems == [] and p.stack == []
    assert "<script" not in page and "http://" not in page.replace("http://127.0.0.1", "")
    assert SECRET not in page
    assert "Poisoned memory triggered send_email" in page and "ASI06" in page


def test_html_escapes_untrusted_content():
    from agentsec.reports.html_report import render_html as r
    rep = {"summary": {"scenarios": 1, "passed": 0, "findings": 1, "errors": 0,
                       "by_severity": {"critical": 1, "high": 0, "medium": 0, "low": 0}, "by_owasp": {}},
           "run_config": {"seed": 0, "replay": "x", "policy": {"agent": {"name": "<b>a</b>", "endpoint": "http://x"}}},
           "tool": {"version": "0"}, "generated_at": "now", "warnings": [],
           "findings": [{"id": "i", "severity": "critical", "title": "<script>alert(1)</script>",
                         "scenario_id": "s", "owasp": [], "policy_violated": "p", "observed_action": "o",
                         "input": "<img src=x onerror=alert(1)>", "remediation": "r", "evidence": [{"c": "</pre>"}]}],
           "scenarios": []}
    page = r(rep)
    assert "<script>alert" not in page and "<img" not in page and "<b>a</b>" not in page


def test_markdown_summary(report):
    md = render_markdown(report)
    assert md.startswith("## Invaris AgentSec") and "| Severity | Finding |" in md
    assert "ASI01" in md
    clean = dict(report, findings=[], summary=dict(report["summary"], findings=0, passed=34))
    assert "No findings." in render_markdown(clean)


def test_github_annotations_escape_and_levels(report):
    lines = annotations(report)
    assert any(l.startswith("::error title=AgentSec CRITICAL::") for l in lines)
    assert any(l.startswith("::warning title=AgentSec MEDIUM::") for l in lines)
    assert _escape_data("a%b\nc") == "a%25b%0Ac"
    assert all("\n" not in l for l in lines)


def test_write_reports_formats(tmp_path, policy_text, safe_url):
    policy = parse_policy(policy_text.format(endpoint=safe_url) + "tests: [prompt_injection]\n")
    suite = run_suite(policy, HTTPAgentAdapter(policy.agent))
    _, paths = write_reports(suite, str(tmp_path), ["json", "html", "markdown"])
    assert [p.rsplit("/", 1)[1] for p in paths] == ["report.json", "report.html", "summary.md"]
    assert json.load(open(paths[0]))["summary"]["scenarios"] == 5


def test_cli_format_and_github_env(tmp_path, monkeypatch, policy_text, vulnerable_url, capsys):
    pol = tmp_path / "p.yaml"
    pol.write_text(policy_text.format(endpoint=vulnerable_url))
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    out = tmp_path / "o"
    assert main(["test", "-p", str(pol), "-o", str(out), "-f", "json", "-s", "loop_and_budget_limits"]) == 1
    assert sorted(x.name for x in out.iterdir()) == ["report.json"]
    assert "::warning title=AgentSec MEDIUM::" in capsys.readouterr().out
    assert "## Invaris AgentSec" in summary.read_text()
    assert main(["test", "-p", str(pol), "-o", str(out), "-f", "pdf"]) == 2
