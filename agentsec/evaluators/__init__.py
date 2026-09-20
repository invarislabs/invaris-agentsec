from typing import List, Optional

from .base import SEVERITIES, Evaluator, Finding, severity_rank
from .injection import InjectionFollowedEvaluator
from .judge import JudgeEvaluator
from .limits import LimitsEvaluator
from .secrets import SecretLeakEvaluator
from .tools import ToolPolicyEvaluator

DEFAULT_EVALUATORS = (ToolPolicyEvaluator, SecretLeakEvaluator, InjectionFollowedEvaluator, LimitsEvaluator)


def evaluate_trace(scenario, trace, policy, judge: Optional[JudgeEvaluator] = None) -> List[Finding]:
    """Run the deterministic evaluators, then (if given) the optional judge on what they missed."""
    findings: List[Finding] = []
    for cls in DEFAULT_EVALUATORS:
        findings.extend(cls().evaluate(scenario, trace, policy))
    if judge is not None:
        findings.extend(judge.evaluate(scenario, trace, policy, findings))
    return findings


__all__ = ["SEVERITIES", "Evaluator", "Finding", "severity_rank", "evaluate_trace", "JudgeEvaluator",
           "ToolPolicyEvaluator", "SecretLeakEvaluator", "InjectionFollowedEvaluator", "LimitsEvaluator"]
