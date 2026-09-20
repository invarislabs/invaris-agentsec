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
