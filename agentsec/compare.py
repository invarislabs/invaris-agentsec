"""Compare two report.json files to spot security regressions between runs."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List

from .evaluators import severity_rank


class CompareError(Exception):
    pass


def load(path: str) -> Dict[str, Any]:
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as exc:
        raise CompareError("cannot read report %s: %s" % (path, exc))
    if not isinstance(data, dict) or "findings" not in data or "scenarios" not in data:
        raise CompareError("%s is not an AgentSec report.json" % path)
    return data


@dataclass
class Comparison:
    new: List[Dict[str, Any]] = field(default_factory=list)
    fixed: List[Dict[str, Any]] = field(default_factory=list)
    unchanged: List[Dict[str, Any]] = field(default_factory=list)
    worse: List[Dict[str, Any]] = field(default_factory=list)      # severity went up
    better: List[Dict[str, Any]] = field(default_factory=list)     # severity went down
    not_comparable: List[Dict[str, Any]] = field(default_factory=list)  # scenario not (cleanly) rerun
    warnings: List[str] = field(default_factory=list)

    def regressions(self, min_severity: str = "low") -> List[Dict[str, Any]]:
        floor = severity_rank(min_severity)
        return [f for f in self.new + self.worse if severity_rank(f["severity"]) >= floor]


def compare(base: Dict[str, Any], head: Dict[str, Any]) -> Comparison:
    out = Comparison()
    b_run, h_run = base.get("run_config", {}), head.get("run_config", {})
    if b_run.get("seed") != h_run.get("seed"):
        out.warnings.append("seeds differ (%s vs %s): canaries and markers differ, so results may not line up"
                            % (b_run.get("seed"), h_run.get("seed")))
    b_sc = {s["id"]: s for s in base["scenarios"]}
    h_sc = {s["id"]: s for s in head["scenarios"]}
    only_base = sorted(set(b_sc) - set(h_sc))
    only_head = sorted(set(h_sc) - set(b_sc))
    if only_base:
        out.warnings.append("%d scenario(s) only in the baseline (their findings are not counted as fixed): %s"
                            % (len(only_base), ", ".join(only_base)))
    if only_head:
        out.warnings.append("%d scenario(s) only in the new run: %s" % (len(only_head), ", ".join(only_head)))
    b_pol = (b_run.get("policy") or {})
    h_pol = (h_run.get("policy") or {})
    if b_pol != h_pol:
        out.warnings.append("the policy differs between the two runs")

    b_f = {f["id"]: f for f in base["findings"]}
    h_f = {f["id"]: f for f in head["findings"]}
    for fid, f in h_f.items():
        if fid not in b_f:
            out.new.append(f)
        else:
            old = severity_rank(b_f[fid]["severity"])
            new = severity_rank(f["severity"])
            (out.worse if new > old else out.better if new < old else out.unchanged).append(f)
    for fid, f in b_f.items():
        if fid in h_f:
            continue
        sc = h_sc.get(f["scenario_id"])
        if sc is None or sc.get("status") == "error":
            out.not_comparable.append(f)   # cannot claim it was fixed
        else:
            out.fixed.append(f)
    return out


def render(c: Comparison) -> str:
    lines: List[str] = []
    for w in c.warnings:
        lines.append("warning: " + w)
    if lines:
        lines.append("")

    def block(title, items, mark):
        if items:
            lines.append("%s (%d)" % (title, len(items)))
            for f in sorted(items, key=lambda x: (-severity_rank(x["severity"]), x["id"])):
                lines.append("  %s %-8s %s  [%s]" % (mark, f["severity"], f["title"], f["scenario_id"]))
            lines.append("")

    block("NEW findings", c.new, "+")
    block("Severity increased", c.worse, "^")
    block("Fixed", c.fixed, "-")
    block("Severity decreased", c.better, "v")
    block("Unchanged", c.unchanged, "=")
    block("Not comparable (scenario missing or errored in the new run)", c.not_comparable, "?")
    lines.append("%d new, %d worse, %d fixed, %d better, %d unchanged" % (
        len(c.new), len(c.worse), len(c.fixed), len(c.better), len(c.unchanged)))
    return "\n".join(lines)
