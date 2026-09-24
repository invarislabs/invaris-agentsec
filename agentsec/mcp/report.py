from __future__ import annotations

import json
import os
import unicodedata
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .. import __version__
from ..evaluators import SEVERITIES, Finding


def build_mcp_report(target: str, server_info: Dict[str, Any], tools: List[Dict[str, Any]],
                     findings: List[Finding], resources: Optional[List[Dict[str, Any]]] = None,
                     prompts: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Same shape as `agentsec test` reports where it matters, so `agentsec compare` works on it.
    `resources` and `prompts` are optional -- most servers only expose tools -- and default to none,
    so existing callers that pass only `tools` and `findings` keep working unchanged."""
    resources = resources or []
    prompts = prompts or []
    by_sev = {s: 0 for s in SEVERITIES}
    for f in findings:
        by_sev[f.severity] += 1
    scenarios = []

    def add(sid: str, title: str) -> None:
        ids = [f.id for f in findings if f.scenario_id == sid]
        scenarios.append({"id": sid, "category": "mcp_server", "title": title,
                          "vector": "tool_definition", "status": "findings" if ids else "passed",
                          "finding_ids": ids})

    for t in tools:
        add("mcp/%s" % t.get("name"), str(t.get("name")))
    for r in resources:
        add("mcp/resource:%s" % r.get("uri"), str(r.get("uri")))
    for p in prompts:
        add("mcp/prompt:%s" % p.get("name"), str(p.get("name")))
    known = {s["id"] for s in scenarios}
    for f in findings:            # findings about items that no longer exist (removed from a pin)
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
                    "tools": len(tools), "resources": len(resources), "prompts": len(prompts)},
        "findings": [f.to_dict() for f in findings],
        "scenarios": scenarios,
        "tools": [{"name": t.get("name"), "description": t.get("description")} for t in tools],
        "resources": [{"uri": r.get("uri"), "name": r.get("name"), "description": r.get("description")}
                      for r in resources],
        "prompts": [{"name": p.get("name"), "description": p.get("description")} for p in prompts],
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
    counts = ["%d tool(s)" % s["tools"]]
    if s.get("resources"):
        counts.append("%d resource(s)" % s["resources"])
    if s.get("prompts"):
        counts.append("%d prompt(s)" % s["prompts"])
    lines = ["MCP scan of %s%s" % (_clean(report["run_config"]["target"]),
                                    " (%s %s)" % (_clean(srv.get("name")), _clean(srv.get("version", ""))) if srv.get("name") else ""),
             "%s, %d finding(s): %s" % (", ".join(counts), s["findings"],
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
