from __future__ import annotations

from typing import List

from ..evaluators import SEVERITIES, severity_rank
from ..runners import SuiteResult
from .json_report import _mask_obj

_COLORS = {"critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[36m"}
_RESET, _BOLD, _DIM = "\033[0m", "\033[1m", "\033[2m"


def render_terminal(suite: SuiteResult, report_path: str = "", color: bool = False,
                    verbose: bool = False) -> str:
    def paint(text: str, code: str) -> str:
        return (code + text + _RESET) if color else text

    total = len(suite.results)
    passed = sum(r.status == "passed" for r in suite.results)
    errors = [r for r in suite.results if r.status == "error"]
    findings = sorted(suite.findings, key=lambda f: -severity_rank(f.severity))

    lines: List[str] = [paint("Invaris AgentSec", _BOLD), ""]
    lines.append("%d scenarios executed" % total)
    lines.append("%d passed" % passed)
    lines.append("%d finding%s" % (len(findings), "" if len(findings) == 1 else "s"))
    if errors:
        lines.append("%d errored (agent unreachable or invalid reply)" % len(errors))
    lines.append("")

    sensitive = suite.policy.resolved_secrets() + [v for f in findings for v in f.sensitive]
    for f in findings:
        label = paint(f.severity.upper().ljust(9), _COLORS[f.severity])
        lines.append("%s %s" % (label, f.title))
        lines.append("          %s" % paint("%s  |  %s" % (f.scenario_id, f.policy_violated), _DIM))
        if verbose:
            observed = _mask_obj(f.observed_action, sensitive)
            lines.append("          observed: %s" % observed)
            lines.append("          fix:      %s" % f.remediation)
    if findings:
        lines.append("")
    for r in errors:
        lines.append("%s %s: %s" % (paint("ERROR".ljust(9), _BOLD), r.scenario.id, r.trace.error))
    for w in suite.warnings:
        lines.append("warning: %s" % w)
    if errors or suite.warnings:
        lines.append("")
    if report_path:
        lines.append("Report written to %s" % report_path)
    return "\n".join(lines)
