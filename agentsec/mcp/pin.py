"""Pin tool definitions so a later scan can detect a "rug pull": a server that changes a tool
definition after the user approved it."""
from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List

from ..evaluators.base import Finding
from .checks import CATEGORY


def _digest(tool: Dict[str, Any]) -> str:
    keep = {k: tool.get(k) for k in ("name", "title", "description", "inputSchema", "annotations")}
    return hashlib.sha256(json.dumps(keep, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def make_pins(tools: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {"version": "1", "tools": {str(t.get("name")): _digest(t) for t in tools if t.get("name")}}


def compare_pins(pins: Dict[str, Any], tools: List[Dict[str, Any]]) -> List[Finding]:
    old = pins.get("tools") or {}
    new = make_pins(tools)["tools"]
    out: List[Finding] = []

    def f(name: str, rule: str, severity: str, title: str, observed: str, remediation: str) -> Finding:
        return Finding(rule=rule, scenario_id="mcp/" + name, category=CATEGORY, severity=severity,
                       title=title, policy_violated="Approved MCP tool definitions must not change silently",
                       observed_action=observed, input="tools/list compared with the pinned definitions",
                       evidence=[{"tool": name, "pinned": old.get(name), "current": new.get(name)}],
                       remediation=remediation)

    for name, digest in sorted(new.items()):
        if name not in old:
            out.append(f(name, "mcp_tool_added", "medium", "New tool `%s` appeared since the pin was made" % name,
                         "tool not in the pin file", "Review the new tool, then re-pin with --pin-write."))
        elif old[name] != digest:
            out.append(f(name, "mcp_definition_changed", "high",
                         "Tool `%s` changed since the pin was made" % name,
                         "definition hash differs from the pin",
                         "Diff the definition and re-approve it before use. Unreviewed changes are a rug-pull risk."))
    for name in sorted(set(old) - set(new)):
        out.append(f(name, "mcp_tool_removed", "low", "Pinned tool `%s` is no longer offered" % name,
                     "tool missing from tools/list", "Confirm the removal is intended, then re-pin."))
    return out
