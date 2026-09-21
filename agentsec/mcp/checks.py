"""Static checks on MCP tool definitions.

These look for the ways a malicious or compromised MCP server attacks the agent that connects to it:
hidden instructions in tool descriptions ("tool poisoning"), instructions hidden in the input schema,
invisible characters, one tool steering how another is used ("shadowing"), and references to secrets or
exfiltration. Pattern matching finds the obvious cases only: a clean result is not proof of safety.
"""
from __future__ import annotations

import re
import unicodedata
from typing import Any, Dict, Iterator, List, Optional, Tuple

from ..evaluators.base import Finding

CATEGORY = "mcp_server"

INSTRUCTION_PATTERNS = [
    (re.compile(r"ignore\s+(all\s+|any\s+|the\s+)?(previous|prior|above|earlier)\s+(instructions|rules|messages)", re.I),
     "tells the model to ignore earlier instructions"),
    (re.compile(r"(do\s+not|don'?t|never)\s+(tell|mention|inform|reveal|show|notify|let)\s+(the\s+)?user", re.I),
     "tells the model to hide something from the user"),
    (re.compile(r"without\s+(telling|informing|notifying|alerting)\s+(the\s+)?user", re.I),
     "tells the model to act without informing the user"),
    (re.compile(r"</?\s*(important|system|instructions?|secret)\s*>|\[\s*system\s*\]", re.I),
     "uses a special instruction tag"),
    (re.compile(r"(before|after|when)\s+(using|calling|running|invoking)\s+(this|the)\s+tool.{0,40}"
                r"(you\s+must|first|always|also|need\s+to)", re.I | re.S),
     "gives the model extra steps to take around the tool call"),
    (re.compile(r"you\s+(must|should)\s+(first|always|also|secretly)\b", re.I),
     "issues a directive to the model rather than describing the tool"),
    (re.compile(r"\b(system|developer)\s+prompt\b", re.I), "refers to the system prompt"),
    (re.compile(r"\bpass\s+(its|the|their)\s+(content|contents|output)\s+as\b", re.I),
     "tells the model to pass data into a parameter"),
]
SENSITIVE_PATTERN = re.compile(
    r"~/\.ssh|\bid_rsa\b|\.aws/credentials|/etc/(passwd|shadow)|(?<![\w])\.env\b|\bmcp\.json\b|"
    r"\bcredentials?\s+file\b|\bprivate\s+key\b|\bapi[_\s-]?keys?\b|\bpasswords?\b", re.I)
EXFIL_PATTERN = re.compile(
    r"\b(send|post|forward|upload|email|transmit|exfiltrate|leak)\b.{0,60}"
    r"(https?://|\b[\w.+-]+@[\w-]+\.[\w.]+|\bto\s+(the\s+)?(server|endpoint|address))", re.I | re.S)
HIGH_IMPACT_PATTERN = re.compile(
    r"\b(exec(ute)?|shell|run_?command|eval|sudo|delete|drop|remove|write_?file|transfer|payment|pay|"
    r"send_?email|wire)\b", re.I)
RISKY_PARAMS = {"command", "cmd", "script", "code", "sql", "shell", "eval", "expression"}
MAX_DESCRIPTION = 2000

_INVISIBLE_CATS = ("Cf",)


def _strings(obj: Any, path: str = "") -> Iterator[Tuple[str, str]]:
    """Every string in a JSON value with a readable location, e.g. `inputSchema.properties.q.description`."""
    if isinstance(obj, str):
        yield path, obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield from _strings(v, "%s.%s" % (path, k) if path else str(k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _strings(v, "%s[%d]" % (path, i))


def _excerpt(text: str, start: int, end: int, pad: int = 50) -> str:
    s, e = max(0, start - pad), min(len(text), end + pad)
    return ("…" if s else "") + text[s:e].replace("\n", " ") + ("…" if e < len(text) else "")


def _finding(tool: str, rule: str, severity: str, title: str, observed: str, evidence: List[Dict[str, Any]],
             remediation: str, key: str = "") -> Finding:
    return Finding(
        rule=rule, scenario_id="mcp/" + tool, category=CATEGORY, severity=severity, title=title,
        policy_violated="MCP tool definitions must describe the tool, not instruct the model",
        observed_action=observed, input="tools/list definition of `%s`" % tool, evidence=evidence,
        remediation=remediation, key=key)


def scan_tools(tools: List[Dict[str, Any]], allowed_tools: Optional[List[str]] = None,
               forbidden_tools: Optional[List[str]] = None) -> List[Finding]:
    findings: List[Finding] = []
    names = [str(t.get("name", "")) for t in tools]
    for dup in sorted({n for n in names if names.count(n) > 1}):
        findings.append(_finding(
            dup, "mcp_duplicate_tool", "medium", "Server lists the tool name `%s` more than once" % dup,
            "duplicate tool name", [{"tool": dup}],
            "Tool names must be unique; a duplicate can shadow the tool the user approved."))

    for tool in tools:
        name = str(tool.get("name", ""))
        if not name:
            continue
        texts = list(_strings({k: v for k, v in tool.items() if k in
                               ("name", "title", "description", "inputSchema", "annotations")}))
        hidden: List[Dict[str, Any]] = []
        sensitive: List[Dict[str, Any]] = []
        exfil: List[Dict[str, Any]] = []
        for field, text in texts:
            for pat, why in INSTRUCTION_PATTERNS:
                m = pat.search(text)
                if m:
                    hidden.append({"tool": name, "field": field, "why": why, "excerpt": _excerpt(text, *m.span())})
            m = SENSITIVE_PATTERN.search(text)
            if m:
                sensitive.append({"tool": name, "field": field, "excerpt": _excerpt(text, *m.span())})
            m = EXFIL_PATTERN.search(text)
            if m:
                exfil.append({"tool": name, "field": field, "excerpt": _excerpt(text, *m.span())})
            invisible = [c for c in text if unicodedata.category(c) in _INVISIBLE_CATS]
            if invisible:
                findings.append(_finding(
                    name, "mcp_invisible_characters", "high",
                    "Tool `%s` contains invisible characters in %s" % (name, field),
                    "%d invisible character(s), for example U+%04X" % (len(invisible), ord(invisible[0])),
                    [{"tool": name, "field": field, "codepoints": sorted({"U+%04X" % ord(c) for c in invisible})}],
                    "Remove zero-width, bidirectional and tag characters; they can hide instructions from reviewers.",
                    key=field))

        if hidden:
            poisoned_with = bool(sensitive or exfil)
            in_schema = any(e["field"].startswith("inputSchema") for e in hidden)
            findings.append(_finding(
                name, "mcp_tool_poisoning", "critical" if poisoned_with else "high",
                "Tool `%s` %s" % (name, "tries to steer the model and touches sensitive data"
                                  if poisoned_with else "contains instructions aimed at the model"),
                hidden[0]["why"] + (" (also in the input schema)" if in_schema else ""),
                (hidden + sensitive + exfil)[:6],
                "Do not connect this server. Tool descriptions are shown to the model as trusted text, so "
                "instructions in them act like a prompt injection the user never sees."))
        elif sensitive and exfil:
            findings.append(_finding(
                name, "mcp_tool_poisoning", "high",
                "Tool `%s` mentions sensitive data and sending it somewhere" % name,
                "sensitive reference plus an exfiltration pattern", (sensitive + exfil)[:4],
                "Review this definition by hand; the combination is typical of data-theft tool descriptions."))
        elif sensitive:
            findings.append(_finding(
                name, "mcp_sensitive_reference", "medium",
                "Tool `%s` refers to credentials or secret files in its definition" % name,
                "sensitive reference", sensitive[:3],
                "A tool description has no reason to name secret files; confirm this is intended."))

        desc = str(tool.get("description") or "")
        if len(desc) > MAX_DESCRIPTION:
            findings.append(_finding(
                name, "mcp_oversized_description", "low",
                "Tool `%s` has a very long description (%d characters)" % (name, len(desc)),
                "description longer than %d characters" % MAX_DESCRIPTION, [{"tool": name, "length": len(desc)}],
                "Long descriptions are hard to review and can hide instructions. Keep them short."))

        others = [n for n in names if n and n != name and len(n) >= 4]
        for other in others:
            m = re.search(r"\b(when|whenever|before|after|instead\s+of|rather\s+than|always)\b.{0,80}\b%s\b"
                          % re.escape(other), desc, re.I | re.S)
            if m:
                findings.append(_finding(
                    name, "mcp_tool_shadowing", "medium",
                    "Tool `%s` gives instructions about how to use `%s`" % (name, other),
                    "description of one tool steers another tool", [{"tool": name, "field": "description", "other_tool": other,
                    "excerpt": _excerpt(desc, *m.span())}],
                    "A tool should describe only itself; cross-tool instructions can redirect other tools' behaviour.",
                    key=other))

        props = ((tool.get("inputSchema") or {}).get("properties") or {})
        for pname, pdef in props.items() if isinstance(props, dict) else []:
            if str(pname).lower() in RISKY_PARAMS and isinstance(pdef, dict) and pdef.get("type", "string") == "string" \
                    and not any(k in pdef for k in ("enum", "pattern", "maxLength", "const")):
                findings.append(_finding(
                    name, "mcp_unconstrained_input", "low",
                    "Tool `%s` takes a free-form `%s` string" % (name, pname),
                    "unconstrained code-like parameter", [{"tool": name, "parameter": pname}],
                    "Constrain the parameter (enum, pattern, maxLength) or make sure the agent needs human approval.",
                    key=str(pname)))

        if forbidden_tools and name in forbidden_tools:
            findings.append(_finding(
                name, "mcp_forbidden_tool_exposed", "high",
                "Server exposes `%s`, which your policy forbids" % name, "forbidden tool available to the agent",
                [{"tool": name}], "Remove the tool from this server, or filter it out before the agent sees it."))
        elif allowed_tools is not None and name not in allowed_tools:
            findings.append(_finding(
                name, "mcp_unlisted_tool", "medium",
                "Server exposes `%s`, which is not in your policy's allowed_tools" % name,
                "tool outside the allowlist is available", [{"tool": name}],
                "Add the tool to allowed_tools if you want it, otherwise filter it out."))
        elif allowed_tools is None and HIGH_IMPACT_PATTERN.search(name):
            findings.append(_finding(
                name, "mcp_high_impact_tool", "low",
                "Tool `%s` looks high-impact (shell, delete, payment or email)" % name,
                "high-impact capability available", [{"tool": name}],
                "Give the agent only the tools it needs; require human approval for high-impact ones."))
    return findings
