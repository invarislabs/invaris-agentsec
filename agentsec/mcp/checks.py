"""Static checks on MCP definitions: tools, resources and prompts.

These look for the ways a malicious or compromised MCP server attacks the agent that connects to it:
hidden instructions in a definition's text ("tool poisoning" -- and the same trick works just as well in
a resource's description or a prompt template, since both are handed to the model too), instructions
hidden in a tool's input schema, invisible characters, one tool steering how another is used
("shadowing"), a tool name built to look like another one already on the server ("confusable" /
homoglyph impersonation), annotations that contradict what a tool's name or description says it does,
and references to secrets or exfiltration. Pattern matching finds the obvious cases only: a clean result
is not proof of safety.
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
    (re.compile(r"\b(instructions?|rules|guidance)\b.{0,60}\bhttps?://", re.I | re.S),
     "points the model to instructions at an external URL, which this scan cannot inspect"),
    (re.compile(r"https?://\S+.{0,60}\b(instructions?|rules|guidance)\b", re.I | re.S),
     "points the model to instructions at an external URL, which this scan cannot inspect"),
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

# A compact map of common look-alike characters to their ASCII equivalent -- enough to catch a tool
# name built from Cyrillic, Greek or fullwidth characters to impersonate a Latin one already on the
# same server. This is not a full Unicode TR39 confusables implementation (that table is large and
# this project doesn't vendor it); it covers the letters attackers actually use for this because they
# render identically to Latin letters in most fonts.
_CONFUSABLES = {
    "а": "a", "с": "c", "е": "e", "о": "o", "р": "p", "х": "x", "у": "y", "і": "i", "ѕ": "s", "ј": "j",
    "һ": "h", "ԁ": "d", "ѵ": "v", "ԛ": "q", "ѡ": "w", "ⅰ": "i", "ⅼ": "l", "ⅽ": "c",   # Cyrillic-ish
    "α": "a", "β": "b", "ϲ": "c", "ε": "e", "η": "n", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p",
    "τ": "t", "υ": "u", "χ": "x", "ɡ": "g",                                            # Greek-ish
    "０": "0", "１": "1", "２": "2", "３": "3", "４": "4", "５": "5", "６": "6", "７": "7", "８": "8", "９": "9",
}


def _skeleton(name: str) -> str:
    normalized = unicodedata.normalize("NFKC", name)
    return "".join(_CONFUSABLES.get(c, c) for c in normalized).casefold()


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


def scenario_id_for(kind: str, ident: str) -> str:
    """`mcp/<name>` for a tool (unchanged from before resources and prompts were scanned, so old
    reports, pins and tests keep working), `mcp/<kind>:<ident>` for a resource or prompt."""
    return "mcp/%s" % ident if kind == "tool" else "mcp/%s:%s" % (kind, ident)


def _finding(kind: str, ident: str, rule: str, severity: str, title: str, observed: str,
             evidence: List[Dict[str, Any]], remediation: str, key: str = "") -> Finding:
    return Finding(
        rule=rule, scenario_id=scenario_id_for(kind, ident), category=CATEGORY, severity=severity, title=title,
        policy_violated="MCP %s definitions must describe the %s, not instruct the model" % (kind, kind),
        observed_action=observed, input="%ss/list definition of `%s`" % (kind, ident), evidence=evidence,
        remediation=remediation, key=key)


def _check_oversized(kind: str, ident: str, desc: str) -> List[Finding]:
    if len(desc) <= MAX_DESCRIPTION:
        return []
    return [_finding(
        kind, ident, "mcp_oversized_description", "low",
        "%s `%s` has a very long description (%d characters)" % (kind.capitalize(), ident, len(desc)),
        "description longer than %d characters" % MAX_DESCRIPTION, [{kind: ident, "length": len(desc)}],
        "Long descriptions are hard to review and can hide instructions. Keep them short.")]


def _scan_texts(kind: str, ident: str, texts: List[Tuple[str, str]]) -> List[Finding]:
    """Instruction / sensitive-reference / exfiltration / invisible-character checks, shared by tools,
    resources and prompts: an MCP server can plant the same hidden-instruction attack in a resource's
    description or a prompt template's own text, not just a tool's description or input schema."""
    findings: List[Finding] = []
    hidden: List[Dict[str, Any]] = []
    sensitive: List[Dict[str, Any]] = []
    exfil: List[Dict[str, Any]] = []
    label = kind.capitalize()
    for field, text in texts:
        for pat, why in INSTRUCTION_PATTERNS:
            m = pat.search(text)
            if m:
                hidden.append({kind: ident, "field": field, "why": why, "excerpt": _excerpt(text, *m.span())})
        m = SENSITIVE_PATTERN.search(text)
        if m:
            sensitive.append({kind: ident, "field": field, "excerpt": _excerpt(text, *m.span())})
        m = EXFIL_PATTERN.search(text)
        if m:
            exfil.append({kind: ident, "field": field, "excerpt": _excerpt(text, *m.span())})
        invisible = [c for c in text if unicodedata.category(c) in _INVISIBLE_CATS]
        if invisible:
            findings.append(_finding(
                kind, ident, "mcp_invisible_characters", "high",
                "%s `%s` contains invisible characters in %s" % (label, ident, field),
                "%d invisible character(s), for example U+%04X" % (len(invisible), ord(invisible[0])),
                [{kind: ident, "field": field, "codepoints": sorted({"U+%04X" % ord(c) for c in invisible})}],
                "Remove zero-width, bidirectional and tag characters; they can hide instructions from reviewers.",
                key=field))

    if hidden:
        poisoned_with = bool(sensitive or exfil)
        in_schema = any(e["field"].startswith("inputSchema") for e in hidden)
        findings.append(_finding(
            kind, ident, "mcp_%s_poisoning" % kind, "critical" if poisoned_with else "high",
            "%s `%s` %s" % (label, ident, "tries to steer the model and touches sensitive data"
                            if poisoned_with else "contains instructions aimed at the model"),
            hidden[0]["why"] + (" (also in the input schema)" if in_schema else ""),
            (hidden + sensitive + exfil)[:6],
            "Do not connect this server. %s definitions are shown to the model as trusted text, so "
            "instructions in them act like a prompt injection the user never sees." % label))
    elif sensitive and exfil:
        findings.append(_finding(
            kind, ident, "mcp_%s_poisoning" % kind, "high",
            "%s `%s` mentions sensitive data and sending it somewhere" % (label, ident),
            "sensitive reference plus an exfiltration pattern", (sensitive + exfil)[:4],
            "Review this definition by hand; the combination is typical of data-theft descriptions."))
    elif sensitive:
        findings.append(_finding(
            kind, ident, "mcp_sensitive_reference", "medium",
            "%s `%s` refers to credentials or secret files in its definition" % (label, ident),
            "sensitive reference", sensitive[:3],
            "A definition has no reason to name secret files; confirm this is intended."))
    return findings


def _looks_destructive(name: str, desc: str) -> bool:
    return bool(HIGH_IMPACT_PATTERN.search(name) or HIGH_IMPACT_PATTERN.search(desc))


def scan_tools(tools: List[Dict[str, Any]], allowed_tools: Optional[List[str]] = None,
               forbidden_tools: Optional[List[str]] = None) -> List[Finding]:
    findings: List[Finding] = []
    names = [str(t.get("name", "")) for t in tools]
    for dup in sorted({n for n in names if names.count(n) > 1}):
        findings.append(_finding(
            "tool", dup, "mcp_duplicate_tool", "medium", "Server lists the tool name `%s` more than once" % dup,
            "duplicate tool name", [{"tool": dup}],
            "Tool names must be unique; a duplicate can shadow the tool the user approved."))

    skeletons: Dict[str, List[str]] = {}
    for n in names:
        if n:
            skeletons.setdefault(_skeleton(n), []).append(n)
    for skel, group in sorted(skeletons.items()):
        uniq = sorted(set(group))
        if len(uniq) > 1:
            for n in uniq:
                others = [x for x in uniq if x != n]
                findings.append(_finding(
                    "tool", n, "mcp_confusable_tool_name", "high",
                    "Tool `%s` is visually near-identical to %s" % (n, " / ".join("`%s`" % x for x in others)),
                    "tool names normalize to the same skeleton using different Unicode characters",
                    [{"tools": uniq}],
                    "Rename the tool to remove the ambiguity. A visual look-alike can impersonate a tool the "
                    "user or agent has already reviewed and trusted -- and, unlike a literal keyword match, "
                    "evades naive checks that look only at the exact tool name.", key=skel))

    for tool in tools:
        name = str(tool.get("name", ""))
        if not name:
            continue
        texts = list(_strings({k: v for k, v in tool.items() if k in
                               ("name", "title", "description", "inputSchema", "annotations")}))
        findings.extend(_scan_texts("tool", name, texts))

        desc = str(tool.get("description") or "")
        findings.extend(_check_oversized("tool", name, desc))

        ann = tool.get("annotations")
        if isinstance(ann, dict) and _looks_destructive(name, desc):
            if ann.get("readOnlyHint") is True:
                findings.append(_finding(
                    "tool", name, "mcp_annotation_mismatch", "medium",
                    "Tool `%s` is annotated read-only but its name or description suggests a destructive action" % name,
                    "annotations.readOnlyHint=true conflicts with an action-like name/description",
                    [{"tool": name, "annotations": ann}],
                    "Annotation hints can be used by a client to skip confirmation; verify them against what "
                    "the tool actually does rather than trusting the server's own declaration.", key="readOnlyHint"))
            if ann.get("destructiveHint") is False:
                findings.append(_finding(
                    "tool", name, "mcp_annotation_mismatch", "medium",
                    "Tool `%s` is annotated non-destructive but its name or description suggests otherwise" % name,
                    "annotations.destructiveHint=false conflicts with an action-like name/description",
                    [{"tool": name, "annotations": ann}],
                    "Annotation hints can be used by a client to skip confirmation; verify them against what "
                    "the tool actually does rather than trusting the server's own declaration.", key="destructiveHint"))

        others = [n for n in names if n and n != name and len(n) >= 4]
        for other in others:
            m = re.search(r"\b(when|whenever|before|after|instead\s+of|rather\s+than|always)\b.{0,80}\b%s\b"
                          % re.escape(other), desc, re.I | re.S)
            if m:
                findings.append(_finding(
                    "tool", name, "mcp_tool_shadowing", "medium",
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
                    "tool", name, "mcp_unconstrained_input", "low",
                    "Tool `%s` takes a free-form `%s` string" % (name, pname),
                    "unconstrained code-like parameter", [{"tool": name, "parameter": pname}],
                    "Constrain the parameter (enum, pattern, maxLength) or make sure the agent needs human approval.",
                    key=str(pname)))

        if forbidden_tools and name in forbidden_tools:
            findings.append(_finding(
                "tool", name, "mcp_forbidden_tool_exposed", "high",
                "Server exposes `%s`, which your policy forbids" % name, "forbidden tool available to the agent",
                [{"tool": name}], "Remove the tool from this server, or filter it out before the agent sees it."))
        elif allowed_tools is not None and name not in allowed_tools:
            findings.append(_finding(
                "tool", name, "mcp_unlisted_tool", "medium",
                "Server exposes `%s`, which is not in your policy's allowed_tools" % name,
                "tool outside the allowlist is available", [{"tool": name}],
                "Add the tool to allowed_tools if you want it, otherwise filter it out."))
        elif allowed_tools is None and HIGH_IMPACT_PATTERN.search(name):
            findings.append(_finding(
                "tool", name, "mcp_high_impact_tool", "low",
                "Tool `%s` looks high-impact (shell, delete, payment or email)" % name,
                "high-impact capability available", [{"tool": name}],
                "Give the agent only the tools it needs; require human approval for high-impact ones."))
    return findings


def scan_resources(resources: List[Dict[str, Any]]) -> List[Finding]:
    """Static checks on MCP resource definitions (`resources/list`): the same instruction, sensitive-
    reference, exfiltration and invisible-character patterns as `scan_tools`, plus a check for
    credentials embedded in the URI itself. A resource's actual content (fetched with `resources/read`)
    is never read here, the same way `scan_tools` never calls a tool."""
    findings: List[Finding] = []
    uris = [str(r.get("uri", "")) for r in resources]
    for dup in sorted({u for u in uris if u and uris.count(u) > 1}):
        findings.append(_finding(
            "resource", dup, "mcp_duplicate_resource", "medium",
            "Server lists the resource `%s` more than once" % dup, "duplicate resource uri", [{"resource": dup}],
            "Resource URIs must be unique; a duplicate can shadow the one the user approved."))

    for res in resources:
        uri = str(res.get("uri", ""))
        if not uri:
            continue
        texts = list(_strings({k: v for k, v in res.items() if k in
                               ("uri", "name", "title", "description", "mimeType", "annotations")}))
        findings.extend(_scan_texts("resource", uri, texts))
        findings.extend(_check_oversized("resource", uri, str(res.get("description") or "")))
        if re.search(r"^[a-zA-Z][\w+.-]*://[^/@\s]+:[^/@\s]+@", uri):
            findings.append(_finding(
                "resource", uri, "mcp_resource_uri_credentials", "medium",
                "Resource `%s` embeds credentials in its URI" % uri, "uri contains a userinfo component",
                [{"resource": uri}],
                "Do not put credentials in a resource URI; use a header or an out-of-band secret store."))
    return findings


def scan_prompts(prompts: List[Dict[str, Any]]) -> List[Finding]:
    """Static checks on MCP prompt definitions (`prompts/list`). A prompt name and description, and
    its arguments' names and descriptions, get the same treatment as a tool's -- a prompt is a
    template that becomes conversation content once fetched, which makes it at least as sensitive a
    place to hide instructions as a tool description. `prompts/get` (which would return the actual
    rendered template) is never called here, the same way `scan_tools` never calls a tool."""
    findings: List[Finding] = []
    names = [str(p.get("name", "")) for p in prompts]
    for dup in sorted({n for n in names if n and names.count(n) > 1}):
        findings.append(_finding(
            "prompt", dup, "mcp_duplicate_prompt", "medium",
            "Server lists the prompt `%s` more than once" % dup, "duplicate prompt name", [{"prompt": dup}],
            "Prompt names must be unique; a duplicate can shadow the one the user approved."))

    for prompt in prompts:
        name = str(prompt.get("name", ""))
        if not name:
            continue
        texts = list(_strings({k: v for k, v in prompt.items() if k in ("name", "title", "description", "arguments")}))
        findings.extend(_scan_texts("prompt", name, texts))
        findings.extend(_check_oversized("prompt", name, str(prompt.get("description") or "")))
    return findings
