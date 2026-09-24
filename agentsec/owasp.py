"""Mapping of AgentSec findings to the OWASP Top 10 for Agentic Applications (2026).

The mapping is Invaris' judgement of the closest category, not an official OWASP
classification, and a finding can map to more than one entry.
Reference: https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/
"""
from __future__ import annotations

from typing import Dict, List

FRAMEWORK = "OWASP Top 10 for Agentic Applications (2026)"
REFERENCE_URL = ("https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-"
                 "the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/")

ASI: Dict[str, str] = {
    "ASI01": "Agent Goal Hijack",
    "ASI02": "Tool Misuse",
    "ASI03": "Identity & Privilege Abuse",
    "ASI04": "Agentic Supply Chain Vulnerabilities",
    "ASI05": "Unexpected Code Execution",
    "ASI06": "Memory & Context Poisoning",
    "ASI07": "Insecure Inter-Agent Communication",
    "ASI08": "Cascading Failures",
    "ASI09": "Human-Agent Trust Exploitation",
    "ASI10": "Rogue Agents",
}

_BY_RULE: Dict[str, List[str]] = {
    "forbidden_action": ["ASI02"],
    "unauthorized_tool": ["ASI02", "ASI03"],
    "secret_leak": ["ASI03"],
    "injection_followed": ["ASI01"],
    "memory_poisoned": ["ASI06", "ASI01"],
    "repeated_calls": ["ASI08"],
    "limit_max_steps": ["ASI08"],
    "limit_max_tool_calls": ["ASI02"],
    "limit_max_tokens": ["ASI02"],
    "limit_max_seconds": ["ASI02"],
    "limit_max_cost_usd": ["ASI02"],
    "mcp_tool_poisoning": ["ASI04", "ASI01"],
    "mcp_resource_poisoning": ["ASI04", "ASI01"],
    "mcp_prompt_poisoning": ["ASI04", "ASI01"],
    "mcp_invisible_characters": ["ASI04", "ASI01"],
    "mcp_tool_shadowing": ["ASI04", "ASI02"],
    "mcp_confusable_tool_name": ["ASI04", "ASI01"],
    "mcp_annotation_mismatch": ["ASI04", "ASI02"],
    "mcp_definition_changed": ["ASI04"],
    "mcp_tool_added": ["ASI04"],
    "mcp_tool_removed": ["ASI04"],
    "mcp_resource_added": ["ASI04"],
    "mcp_resource_removed": ["ASI04"],
    "mcp_prompt_added": ["ASI04"],
    "mcp_prompt_removed": ["ASI04"],
    "mcp_duplicate_tool": ["ASI04"],
    "mcp_duplicate_resource": ["ASI04"],
    "mcp_duplicate_prompt": ["ASI04"],
    "mcp_sensitive_reference": ["ASI03", "ASI04"],
    "mcp_resource_uri_credentials": ["ASI03", "ASI04"],
    "mcp_forbidden_tool_exposed": ["ASI02"],
    "mcp_unlisted_tool": ["ASI02", "ASI03"],
    "mcp_high_impact_tool": ["ASI02"],
    "mcp_unconstrained_input": ["ASI05"],
    "mcp_oversized_description": ["ASI04"],
    "judge_goal_hijack": ["ASI01"],
    "judge_paraphrased_leak": ["ASI03"],
}

# Tool misuse caused by adversarial content is also a goal hijack.
_HIJACK_CATEGORIES = {"prompt_injection", "indirect_prompt_injection",
                      "tool_output_poisoning", "memory_poisoning"}


def map_finding(rule: str, category: str) -> List[Dict[str, str]]:
    ids = list(_BY_RULE.get(rule, []))
    if rule in ("forbidden_action", "unauthorized_tool") and category in _HIJACK_CATEGORIES:
        ids.append("ASI01")
    if rule == "secret_leak" and category == "memory_poisoning":
        ids = ["ASI06", "ASI03"]
    seen: List[str] = []
    for i in ids:
        if i not in seen:
            seen.append(i)
    return [{"id": i, "name": ASI[i]} for i in seen]
