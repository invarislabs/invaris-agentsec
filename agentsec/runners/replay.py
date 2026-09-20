"""Replay findings from a saved report to check whether they still reproduce.

The report records the seed, so the same scenarios (same canaries and markers) are
rebuilt and run again against the agent. Use it to confirm a fix, or to check that a
finding is real and not a one-off."""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from ..adapters import AgentAdapter
from ..evaluators import Finding
from ..policies import Policy, PolicyError
from .local import SuiteResult, run_suite


class ReplayError(PolicyError):
    """The report cannot be replayed. The message is user-facing."""


@dataclass
class ReplayOutcome:
    finding_id: str
    title: str
    severity: str
    scenario_id: str
    status: str  # reproduced | not_reproduced | error


@dataclass
class ReplayResult:
    seed: int
    outcomes: List[ReplayOutcome]
    new_findings: List[Finding]
    suite: Optional[SuiteResult]
    policy_changed: bool
    skipped_model_assisted: int = 0

    @property
    def reproduced(self) -> List[ReplayOutcome]:
        return [o for o in self.outcomes if o.status == "reproduced"]

    @property
    def errors(self) -> List[ReplayOutcome]:
        return [o for o in self.outcomes if o.status == "error"]


def load_report(path: str) -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            report = json.load(fh)
    except OSError as exc:
        raise ReplayError("cannot read report %s: %s" % (path, exc))
    except ValueError as exc:
        raise ReplayError("%s is not valid JSON: %s" % (path, exc))
    if not (isinstance(report, dict) and "findings" in report and "scenarios" in report
            and isinstance(report.get("run_config"), dict) and "seed" in report["run_config"]):
        raise ReplayError("%s does not look like an AgentSec report" % path)
    return report


def replay(report: Dict[str, Any], policy: Policy, adapter: AgentAdapter,
           finding_ids: Optional[List[str]] = None,
           scenario_ids: Optional[List[str]] = None, judge: bool = False) -> ReplayResult:
    seed = int(report["run_config"]["seed"])
    known = {f["id"]: f for f in report["findings"]}
    known_scenarios = {s["id"] for s in report["scenarios"]}

    for fid in finding_ids or []:
        if fid not in known:
            raise ReplayError("finding %r is not in the report" % fid)
    for sid in scenario_ids or []:
        if sid not in known_scenarios:
            raise ReplayError("scenario %r is not in the report" % sid)

    if finding_ids:
        targets = [known[f] for f in finding_ids]
    elif scenario_ids:
        targets = [f for f in report["findings"] if f["scenario_id"] in scenario_ids]
    else:
        targets = list(report["findings"])
    skipped = 0
    if not judge:  # model-assisted findings can only be re-checked with the judge enabled
        kept = [t for t in targets if t.get("source", "deterministic") != "model-assisted"]
        skipped, targets = len(targets) - len(kept), kept
    changed = report["run_config"].get("policy", {}).get("source_sha256") not in ("", None, policy.source_sha256)
    if not targets:
        return ReplayResult(seed, [], [], None, changed, skipped)

    scenario_set = sorted({t["scenario_id"] for t in targets})
    categories = sorted({sid.split("/", 1)[0] for sid in scenario_set})
    suite = run_suite(policy, adapter, seed=seed, only=scenario_set, categories=categories, judge=judge)

    errored = {r.scenario.id for r in suite.results if r.status == "error"}
    now = {f.id: f for f in suite.findings}
    outcomes = []
    for t in targets:
        if t["scenario_id"] in errored:
            status = "error"
        else:
            status = "reproduced" if t["id"] in now else "not_reproduced"
        outcomes.append(ReplayOutcome(t["id"], t["title"], t["severity"], t["scenario_id"], status))
    original_ids = {f["id"] for f in report["findings"]}
    new = [f for f in suite.findings if f.id not in original_ids]
    return ReplayResult(seed, outcomes, new, suite, changed, skipped)
