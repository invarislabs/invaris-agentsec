from typing import List, Optional

from .base import SEVERITIES, Evaluator, Finding, severity_rank
from .injection import InjectionFollowedEvaluator
from .judge import JudgeEvaluator
from .limits import LimitsEvaluator
from .secrets import SecretLeakEvaluator
from .spend import AddressAllowlistEvaluator, SpendPolicyEvaluator
from .tools import ToolPolicyEvaluator

DEFAULT_EVALUATORS = (ToolPolicyEvaluator, SecretLeakEvaluator, InjectionFollowedEvaluator, LimitsEvaluator,
                      SpendPolicyEvaluator, AddressAllowlistEvaluator)


def evaluate_trace(scenario, trace, policy, judge: Optional[JudgeEvaluator] = None,
                   extra_evaluators: Optional[List[type]] = None) -> List[Finding]:
    """Run the deterministic evaluators -- built-in, then any attack-pack-provided ones -- then
    (if given) the optional judge on what they all missed. `extra_evaluators` are Evaluator
    subclasses from `agentsec.attacks.packs.load_packs_evaluators`; see docs/extending.md."""
    findings: List[Finding] = []
    for cls in DEFAULT_EVALUATORS:
        findings.extend(cls().evaluate(scenario, trace, policy))
    for cls in (extra_evaluators or []):
        findings.extend(cls().evaluate(scenario, trace, policy))
    if judge is not None:
        findings.extend(judge.evaluate(scenario, trace, policy, findings))
    return findings


__all__ = ["SEVERITIES", "Evaluator", "Finding", "severity_rank", "evaluate_trace", "JudgeEvaluator",
           "ToolPolicyEvaluator", "SecretLeakEvaluator", "InjectionFollowedEvaluator", "LimitsEvaluator",
           "SpendPolicyEvaluator", "AddressAllowlistEvaluator"]
