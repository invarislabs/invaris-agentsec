from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .. import __version__
from ..evaluators import SEVERITIES
from ..owasp import ASI, FRAMEWORK, REFERENCE_URL
from ..evaluators.goals import payload_delivery, was_delivered
from ..runners import SuiteResult

REPORT_SCHEMA_VERSION = "1"


def mask(value: str) -> str:
    """Keep just enough of a secret to recognise it: first 4 and last 2 characters."""
    if len(value) <= 8:
        return "[REDACTED]"
    return "%s…%s [REDACTED]" % (value[:4], value[-2:])


def _mask_obj(obj: Any, sensitive: List[str]) -> Any:
    if isinstance(obj, str):
        for s in sensitive:
            if s and s in obj:
                obj = obj.replace(s, mask(s))
        return obj
    if isinstance(obj, list):
        return [_mask_obj(v, sensitive) for v in obj]
    if isinstance(obj, dict):
        return {k: _mask_obj(v, sensitive) for k, v in obj.items()}
    return obj


def _delivery(result) -> Optional[Dict[str, Any]]:
    """Delivery record for a scenario that tracks it (`Scenario.exposure`); None otherwise.
    The exposure strings themselves are not written: the trace already holds the content, and the
    record says where it arrived."""
    if not getattr(result.scenario, "exposure", None):
        return None
    ev = payload_delivery(result.scenario, result.trace)
    if ev is None:
        return {"tracked": True, "delivered": False, "seq": None, "tool": None}
    return {"tracked": True, "delivered": True, "seq": ev.seq, "tool": ev.tool_name}


def _attack_goals(result) -> Optional[List[Dict[str, Any]]]:
    """The scenario's declared attack goals and whether each was achieved. `sensitive_values` (the
    victim data an attack tries to carry out) are never written, only whether a goal declares any."""
    goals = getattr(result.scenario, "attack_goals", None) or []
    if not goals:
        return None
    achieved = {f.key for f in result.findings if f.rule == "attack_goal_achieved"}
    delivered = was_delivered(result.scenario, result.trace)
    out = []
    for i, g in enumerate(goals):
        out.append({"description": g.description, "tools": list(g.tools), "indicators": list(g.match_any),
                    "carries_victim_data": bool(g.sensitive_values), "severity": g.severity,
                    # None: the payload never arrived, so the goal was not tested
                    "achieved": (str(i) in achieved) if delivered else None})
    return out


def agent_reported(suite: SuiteResult) -> List[Dict[str, str]]:
    """Distinct self-descriptions the agent sent (x_agentsec.agent), in first-seen order."""
    seen: List[Dict[str, str]] = []
    for r in suite.results:
        for e in r.trace.events:
            a = (e.meta or {}).get("agent")
            if isinstance(a, dict) and a not in seen:
                seen.append(a)
    return seen


def build_report(suite: SuiteResult, policy_path: Optional[str] = None) -> Dict[str, Any]:
    # Secrets (configured or detected) are masked everywhere in the report.
    sensitive = list(suite.policy.resolved_secrets())
    for f in suite.findings:
        sensitive.extend(f.sensitive)
    sensitive = sorted(set(sensitive), key=len, reverse=True)

    by_sev = {s: 0 for s in SEVERITIES}
    for f in suite.findings:
        by_sev[f.severity] += 1
    by_owasp: Dict[str, int] = {}
    for f in suite.findings:
        for ref in f.owasp:
            by_owasp[ref["id"]] = by_owasp.get(ref["id"], 0) + 1
    scenarios = []
    for r in suite.results:
        entry: Dict[str, Any] = {
            "id": r.scenario.id, "category": r.scenario.category, "title": r.scenario.title,
            "vector": r.scenario.vector, "status": r.status,
            "finding_ids": [f.id for f in r.findings], "trace": r.trace.to_dict(),
        }
        # Only for scenarios that use these features (attack packs); built-in scenarios are unchanged.
        delivery, goals = _delivery(r), _attack_goals(r)
        if delivery is not None:
            entry["delivery"] = delivery
        if goals is not None:
            entry["attack_goals"] = goals
        scenarios.append(entry)
    run_config: Dict[str, Any] = {
        "seed": suite.seed,
        "policy": suite.policy.to_report_dict(),
        "policy_path": policy_path,
        "scenario_ids": [r.scenario.id for r in suite.results],
        "replay": "agentsec test --policy %s --seed %d" % (policy_path or "<policy>", suite.seed),
    }
    reported = agent_reported(suite)
    if reported:
        run_config["agent_reported"] = reported
    report = {
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "tool": {"name": "invaris-agentsec", "version": __version__},
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "run_config": run_config,
        "summary": {
            "scenarios": len(suite.results),
            "passed": sum(r.status == "passed" for r in suite.results),
            "with_findings": sum(r.status == "findings" for r in suite.results),
            "errors": sum(r.status == "error" for r in suite.results),
            "not_observable": sum(r.status == "not_observable" for r in suite.results),
            "inconclusive": sum(r.status == "inconclusive" for r in suite.results),
            "findings": len(suite.findings),
            "by_severity": by_sev,
            "by_owasp": {k: by_owasp[k] for k in sorted(by_owasp)},
        },
        "owasp_framework": {"name": FRAMEWORK, "url": REFERENCE_URL, "categories": ASI},
        "warnings": suite.warnings,
        "findings": [f.to_dict() for f in suite.findings],
        "scenarios": scenarios,
    }
    return _mask_obj(report, sensitive)


def write_json_report(suite: SuiteResult, out_dir: str, policy_path: Optional[str] = None) -> str:
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "report.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(build_report(suite, policy_path), fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    return path
