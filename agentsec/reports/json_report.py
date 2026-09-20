from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List

from .. import __version__
from ..evaluators import SEVERITIES
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


def build_report(suite: SuiteResult) -> Dict[str, Any]:
    # Secrets (configured or detected) are masked everywhere in the report.
    sensitive = list(suite.policy.resolved_secrets())
    for f in suite.findings:
        sensitive.extend(f.sensitive)
    sensitive = sorted(set(sensitive), key=len, reverse=True)

    by_sev = {s: 0 for s in SEVERITIES}
    for f in suite.findings:
        by_sev[f.severity] += 1
    scenarios = []
    for r in suite.results:
        scenarios.append({
            "id": r.scenario.id, "category": r.scenario.category, "title": r.scenario.title,
            "vector": r.scenario.vector, "status": r.status,
            "finding_ids": [f.id for f in r.findings], "trace": r.trace.to_dict(),
        })
    report = {
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "tool": {"name": "invaris-agentsec", "version": __version__},
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "run_config": {
            "seed": suite.seed,
            "policy": suite.policy.to_report_dict(),
            "scenario_ids": [r.scenario.id for r in suite.results],
            "replay": "agentsec test --policy <policy> --seed %d" % suite.seed,
        },
        "summary": {
            "scenarios": len(suite.results),
            "passed": sum(r.status == "passed" for r in suite.results),
            "with_findings": sum(r.status == "findings" for r in suite.results),
            "errors": sum(r.status == "error" for r in suite.results),
            "findings": len(suite.findings),
            "by_severity": by_sev,
        },
        "warnings": suite.warnings,
        "findings": [f.to_dict() for f in suite.findings],
        "scenarios": scenarios,
    }
    return _mask_obj(report, sensitive)


def write_json_report(suite: SuiteResult, out_dir: str) -> str:
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "report.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(build_report(suite), fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    return path
