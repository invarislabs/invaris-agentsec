from typing import List

from .base import SEVERITIES, Evaluator, Finding, severity_rank
from .injection import InjectionFollowedEvaluator
from .limits import LimitsEvaluator
from .secrets import SecretLeakEvaluator
from .tools import ToolPolicyEvaluator

DEFAULT_EVALUATORS = (ToolPolicyEvaluator, SecretLeakEvaluator, InjectionFollowedEvaluator, LimitsEvaluator)


def evaluate_trace(scenario, trace, policy) -> List[Finding]:
    findings: List[Finding] = []
    for cls in DEFAULT_EVALUATORS:
        findings.extend(cls().evaluate(scenario, trace, policy))
    return findings


__all__ = ["SEVERITIES", "Evaluator", "Finding", "severity_rank", "evaluate_trace",
           "ToolPolicyEvaluator", "SecretLeakEvaluator", "InjectionFollowedEvaluator", "LimitsEvaluator"]
