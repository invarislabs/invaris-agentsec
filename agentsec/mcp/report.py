from __future__ import annotations

import json
import os
import unicodedata
from datetime import datetime, timezone
from typing import Any, Dict, List

from .. import __version__
from ..evaluators import SEVERITIES, Finding


def build_mcp_report(target: str, server_info: Dict[str, Any], tools: List[Dict[str, Any]],
                     findings: List[Finding]) -> Dict[str, Any]:
    """Same shape as `agentsec test` reports where it matters, so `agentsec compare` works on it."""
    by_sev = {s: 0 for s in SEVERITIES}
    for f in findings:
        by_sev[f.severity] += 1
    scenarios = []
    for t in tools:
        ids = [f.id for f in findings if f.scenario_id == "mcp/%s" % t.get("name")]
        scenarios.append({"id": "mcp/%s" % t.get("name"), "category": "mcp_server", "title": str(t.get("name")),
                          "vector": "tool_definition", "status": "findings" if ids else "passed",
                          "finding_ids": ids})
    known = {s["id"] for s in scenarios}
    for f in findings:            # findings about tools that no longer exist (removed from a pin)
        if f.scenario_id not in known:
            known.add(f.scenario_id)
            scenarios.append({"id": f.scenario_id, "category": "mcp_server", "title": f.scenario_id[4:],
                              "vector": "tool_definition", "status": "findings", "finding_ids": [f.id]})
    return {
        "report_schema_version": "1", "kind": "mcp_scan",
        "tool": {"name": "invaris-agentsec", "version": __version__},
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "run_config": {"seed": 0, "target": target, "server": server_info, "policy": {}},
        "summary": {"scenarios": len(scenarios), "findings": len(findings), "by_severity": by_sev,
                    "tools": len(tools)},
        "findings": [f.to_dict() for f in findings],
        "scenarios": scenarios,
        "tools": [{"name": t.get("name"), "description": t.get("description")} for t in tools],
    }


def write_mcp_report(report: Dict[str, Any], out_dir: str) -> str:
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "mcp-report.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    return path


def _clean(text: Any) -> str:
    """Server-supplied text goes to a terminal: show control and invisible characters as escapes."""
    return "".join(c if (c == " " or (c.isprintable() and unicodedata.category(c) != "Cf")) else "\\u%04x" % ord(c)
                   for c in str(text))


def render_mcp_terminal(report: Dict[str, Any]) -> str:
    s = report["summary"]
    srv = report["run_config"].get("server") or {}
    lines = ["MCP scan of %s%s" % (_clean(report["run_config"]["target"]),
                                    " (%s %s)" % (_clean(srv.get("name")), _clean(srv.get("version", ""))) if srv.get("name") else ""),
             "%d tool(s), %d finding(s): %s" % (s["tools"], s["findings"],
                                                 ", ".join("%d %s" % (s["by_severity"][k], k) for k in SEVERITIES)), ""]
    for f in sorted(report["findings"], key=lambda x: SEVERITIES.index(x["severity"])):
        lines.append("[%s] %s" % (f["severity"].upper(), _clean(f["title"])))
        lines.append("    %s" % f["observed_action"])
        for ev in f["evidence"][:2]:
            if ev.get("excerpt"):
                lines.append("    %s: %s" % (_clean(ev.get("field", "")), _clean(ev["excerpt"])))
    if not report["findings"]:
        lines.append("No findings. Static checks only cover known patterns; this is not proof the server is safe.")
    return "\n".join(lines)
