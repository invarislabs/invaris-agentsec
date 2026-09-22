"""Adversarial scenario library. Each category module exposes build(ctx) -> [Scenario]."""
from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Tuple

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
                    categories: Optional[List[str]] = None,
                    extra_categories: Optional[Dict[str, "PackCategory"]] = None
                    ) -> Tuple[List[Scenario], List[str]]:
    """Scenarios for the policy's `tests` (all categories if empty), or for `categories`
    when given. `only` filters by category name or scenario id.

    `extra_categories` (from `agentsec.attacks.packs.load_packs`) adds attack-pack categories for
    this run on top of whatever the policy's own `attack_packs` already loaded. Returns (scenarios, warnings).
    """
    from .packs import PackCategory, check_pack_scenarios, load_packs  # avoid a hard, always-on import

    packs = load_packs(ctx.policy.attack_packs, CATEGORIES) if ctx.policy.attack_packs else {}
    for name, pc in (extra_categories or {}).items():
        packs[name] = pc  # ad hoc packs (e.g. CLI --attack-pack) take precedence over the policy's own

    builders: Dict[str, Any] = dict(CATEGORIES)
    builders.update({name: pc.build for name, pc in packs.items()})
    available = list(CATEGORIES) + list(packs)

    requested = categories or ctx.policy.tests or available
    warnings: List[str] = []
    names: List[str] = []
    for name in requested:
        if name in builders:
            if name not in names:
                names.append(name)
        elif name in PLANNED:
            warnings.append("%s is planned for %s and was skipped" % (name, PLANNED[name]))
        else:
            raise PolicyError("unknown test category %r; available: %s"
                              % (name, ", ".join(available)))
    scenarios: List[Scenario] = []
    for n in names:
        built = builders[n](ctx)
        if n in packs:
            check_pack_scenarios(packs[n].spec, n, built)
        scenarios.extend(built)
    if only:
        scenarios = [s for s in scenarios if s.id in only or s.category in only]
        if not scenarios:
            raise PolicyError("no scenarios match --scenario %s" % ", ".join(only))
    return scenarios, warnings


__all__ = ["CATEGORIES", "PLANNED", "Followup", "Scenario", "ScenarioContext", "build_scenarios"]
