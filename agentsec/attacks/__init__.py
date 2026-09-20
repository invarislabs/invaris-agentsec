"""Adversarial scenario library. Each category module exposes build(ctx) -> [Scenario]."""
from __future__ import annotations

from typing import Callable, Dict, List, Optional, Tuple

from ..policies import PolicyError
from . import (indirect_prompt_injection, loop_and_budget_limits, memory_poisoning, prompt_injection,
               secret_extraction, tool_output_poisoning, unauthorized_tool_use,
               unsafe_retrieved_documents)
from .base import Followup, Scenario, ScenarioContext

# Order matches the categories listed in the README policy example.
CATEGORIES: Dict[str, Callable[[ScenarioContext], List[Scenario]]] = {
    "prompt_injection": prompt_injection.build,
    "indirect_prompt_injection": indirect_prompt_injection.build,
    "secret_extraction": secret_extraction.build,
    "unauthorized_tool_use": unauthorized_tool_use.build,
    "tool_output_poisoning": tool_output_poisoning.build,
    "unsafe_retrieved_documents": unsafe_retrieved_documents.build,
    "loop_and_budget_limits": loop_and_budget_limits.build,
    "memory_poisoning": memory_poisoning.build,
}

# Recognised in policies but not implemented yet.
PLANNED: Dict[str, str] = {}


def build_scenarios(ctx: ScenarioContext, only: Optional[List[str]] = None,
                    categories: Optional[List[str]] = None) -> Tuple[List[Scenario], List[str]]:
    """Scenarios for the policy's `tests` (all categories if empty), or for `categories`
    when given. `only` filters by category name or scenario id. Returns (scenarios, warnings)."""
    requested = categories or ctx.policy.tests or list(CATEGORIES)
    warnings: List[str] = []
    names: List[str] = []
    for name in requested:
        if name in CATEGORIES:
            if name not in names:
                names.append(name)
        elif name in PLANNED:
            warnings.append("%s is planned for %s and was skipped" % (name, PLANNED[name]))
        else:
            raise PolicyError("unknown test category %r; available: %s"
                              % (name, ", ".join(CATEGORIES)))
    scenarios = [s for n in names for s in CATEGORIES[n](ctx)]
    if only:
        scenarios = [s for s in scenarios if s.id in only or s.category in only]
        if not scenarios:
            raise PolicyError("no scenarios match --scenario %s" % ", ".join(only))
    return scenarios, warnings


__all__ = ["CATEGORIES", "PLANNED", "Followup", "Scenario", "ScenarioContext", "build_scenarios"]
