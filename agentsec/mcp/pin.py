"""Pin definitions so a later scan can detect a "rug pull": a server that changes a tool, resource
or prompt definition after the user approved it."""
from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional

from ..evaluators.base import Finding
from .checks import CATEGORY, scenario_id_for

_TOOL_KEYS = ("name", "title", "description", "inputSchema", "annotations")
_RESOURCE_KEYS = ("uri", "name", "title", "description", "mimeType", "annotations")
_PROMPT_KEYS = ("name", "title", "description", "arguments")
_IDENT_KEY = {"tool": "name", "resource": "uri", "prompt": "name"}
_KEYS = {"tool": _TOOL_KEYS, "resource": _RESOURCE_KEYS, "prompt": _PROMPT_KEYS}


def _digest(item: Dict[str, Any], keys) -> str:
    keep = {k: item.get(k) for k in keys}
    return hashlib.sha256(json.dumps(keep, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def _pins_for(kind: str, items: List[Dict[str, Any]]) -> Dict[str, str]:
    ident_key = _IDENT_KEY[kind]
    return {str(item.get(ident_key)): _digest(item, _KEYS[kind]) for item in items if item.get(ident_key)}


def make_pins(tools: List[Dict[str, Any]], resources: Optional[List[Dict[str, Any]]] = None,
             prompts: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    return {
        "version": "2",
        "tools": _pins_for("tool", tools),
        "resources": _pins_for("resource", resources or []),
        "prompts": _pins_for("prompt", prompts or []),
    }


def _diff(kind: str, old: Dict[str, str], new: Dict[str, str]) -> List[Finding]:
    out: List[Finding] = []
    label = kind.capitalize()

    def f(ident: str, rule: str, severity: str, title: str, observed: str, remediation: str) -> Finding:
        return Finding(rule=rule, scenario_id=scenario_id_for(kind, ident), category=CATEGORY, severity=severity,
                       title=title, policy_violated="Approved MCP %s definitions must not change silently" % kind,
                       observed_action=observed, input="%ss/list compared with the pinned definitions" % kind,
                       evidence=[{kind: ident, "pinned": old.get(ident), "current": new.get(ident)}],
                       remediation=remediation)

    for ident, digest in sorted(new.items()):
        if ident not in old:
            out.append(f(ident, "mcp_%s_added" % kind, "medium",
                        "New %s `%s` appeared since the pin was made" % (kind, ident),
                        "%s not in the pin file" % kind, "Review the new %s, then re-pin with --pin-write." % kind))
        elif old[ident] != digest:
            out.append(f(ident, "mcp_definition_changed", "high",
                        "%s `%s` changed since the pin was made" % (label, ident),
                        "definition hash differs from the pin",
                        "Diff the definition and re-approve it before use. Unreviewed changes are a rug-pull risk."))
    for ident in sorted(set(old) - set(new)):
        out.append(f(ident, "mcp_%s_removed" % kind, "low", "Pinned %s `%s` is no longer offered" % (kind, ident),
                    "%s missing from the listing" % kind, "Confirm the removal is intended, then re-pin."))
    return out


def compare_pins(pins: Dict[str, Any], tools: List[Dict[str, Any]],
                 resources: Optional[List[Dict[str, Any]]] = None,
                 prompts: Optional[List[Dict[str, Any]]] = None) -> List[Finding]:
    """`pins` may be a version-1 pin file (tools only, no `resources`/`prompts` keys); those are
    read as empty, so an old pin file just means nothing is pinned yet for the new kinds."""
    new = make_pins(tools, resources, prompts)
    out: List[Finding] = []
    out += _diff("tool", pins.get("tools") or {}, new["tools"])
    out += _diff("resource", pins.get("resources") or {}, new["resources"])
    out += _diff("prompt", pins.get("prompts") or {}, new["prompts"])
    return out
