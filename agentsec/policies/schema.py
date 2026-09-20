"""Security policy (agentsec.yaml, schema version 1)."""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

POLICY_VERSION = "1"


class PolicyError(ValueError):
    """Raised when a policy file is invalid. The message is user-facing."""


@dataclass
class Pricing:
    input_per_1k: float = 0.0
    output_per_1k: float = 0.0


@dataclass
class AgentConfig:
    name: str
    endpoint: str
    model: str = "agentsec-target"
    api_key_env: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    timeout_s: float = 30.0
    declare_tools: bool = True
    retrieval_tools: List[str] = field(default_factory=list)
    pricing: Optional[Pricing] = None


@dataclass
class Limits:
    max_steps: int = 12
    max_tool_calls: int = 10
    max_repeated_calls: int = 3
    max_tokens: Optional[int] = None
    max_seconds: Optional[float] = None
    max_cost_usd: Optional[float] = None


JUDGE_CHECKS = ("goal_hijack", "paraphrased_leak")


@dataclass
class JudgeConfig:
    """Optional model-assisted evaluation. Transcripts (with configured secrets masked)
    are sent to this endpoint, so use a local or trusted model."""
    endpoint: str
    model: str = "judge"
    api_key_env: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    timeout_s: float = 60.0
    checks: List[str] = field(default_factory=lambda: list(JUDGE_CHECKS))
    min_confidence: float = 0.7
    severity: str = "medium"  # severity given to model-assisted findings


@dataclass
class Policy:
    agent: AgentConfig
    allowed_tools: Optional[List[str]] = None  # None = no allowlist enforced
    forbidden_actions: List[str] = field(default_factory=list)
    secrets: List[str] = field(default_factory=list)  # literal values that must never leak
    limits: Limits = field(default_factory=Limits)
    tests: List[str] = field(default_factory=list)
    judge: Optional[JudgeConfig] = None
    version: str = POLICY_VERSION
    source_sha256: str = ""

    def resolved_secrets(self) -> List[str]:
        """Secret values, resolving `env:NAME` references. Unset env vars are skipped."""
        out = []
        for s in self.secrets:
            if s.startswith("env:"):
                value = os.environ.get(s[4:])
                if value:
                    out.append(value)
            elif s:
                out.append(s)
        return out

    def to_report_dict(self) -> Dict[str, Any]:
        """Policy as recorded in reports. Secret values are never included."""
        a = self.agent
        return {
            "version": self.version,
            "agent": {
                "name": a.name, "endpoint": a.endpoint, "model": a.model,
                "api_key_env": a.api_key_env, "timeout_s": a.timeout_s,
                "declare_tools": a.declare_tools, "retrieval_tools": a.retrieval_tools,
            },
            "allowed_tools": self.allowed_tools,
            "forbidden_actions": self.forbidden_actions,
            "secrets_count": len(self.secrets),
            "limits": self.limits.__dict__.copy(),
            "tests": self.tests,
            "judge": ({"endpoint": self.judge.endpoint, "model": self.judge.model,
                       "checks": self.judge.checks, "min_confidence": self.judge.min_confidence,
                       "severity": self.judge.severity} if self.judge else None),
            "source_sha256": self.source_sha256,
        }


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
