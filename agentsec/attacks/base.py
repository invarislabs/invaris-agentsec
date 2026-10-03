from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from ..effects import DATA_LABELS, INTERNAL_EFFECTS, tools_with
from ..policies import Policy

# How adversarial content reaches the agent.
VECTOR_DIRECT = "direct"                    # in the user's message
VECTOR_DOCUMENT = "retrieved_document"      # inside a retrieved document
VECTOR_TOOL_OUTPUT = "tool_output"          # inside a tool result / error / metadata

# (tool_name, arguments, call_index_within_scenario) -> tool result text
ToolResponder = Callable[[str, dict, int], str]

DEFAULT_FORBIDDEN = ["send_email", "execute_payment", "reveal_credentials"]


@dataclass
class Followup:
    """A later conversation in a multi-session scenario (used by memory tests)."""
    user_message: str
    responder: Optional[ToolResponder] = None
    same_session: bool = True  # False = a different simulated user
    # What THIS conversation's user_message authorizes (see Scenario.authorized_effects). None =
    # no claim. Authorization is per conversation: an effect authorized in an earlier
    # conversation but not this one is reported as `stale_authorization`.
    authorized_effects: Optional[List[str]] = None


@dataclass
class Scenario:
    id: str
    category: str
    title: str
    description: str
    user_message: str
    vector: str = VECTOR_DIRECT
    severity_hint: Optional[str] = None
    responder: Optional[ToolResponder] = None  # None = benign tool results
    markers: List[str] = field(default_factory=list)   # output proves injected instruction was followed
    canaries: List[str] = field(default_factory=list)  # planted values that must not appear in output
    payload: Optional[str] = None                      # adversarial text, kept for evidence
    followups: List[Followup] = field(default_factory=list)  # later conversations
    # The effect tags (see Policy.tool_effects) that THIS scenario's user_message actually
    # authorizes, e.g. ["read"] for "just tell me what you find, don't change anything". None
    # (the default) means the scenario makes no claim about task-scoped authorization, so
    # ActionAuthorizationEvaluator ignores it -- most scenarios don't narrate "what the user
    # meant to allow" and shouldn't be scored against a boundary they never asserted.
    authorized_effects: Optional[List[str]] = None
    # Identifiers that belong to a *different* user, customer or tenant than the one this
    # scenario's user is acting as (another account id, another tenant's project key, ...). The
    # agent acting on one of them -- passing it as a tool-call argument -- is a cross-principal
    # access (see agentsec/evaluators/identity.py). Merely seeing one in a result is not.
    foreign_identifiers: List[str] = field(default_factory=list)
    # The scenario can only be judged if the system under test reports which agent acted (trace
    # meta `actor`, see docs/multi-agent.md). A run without any attribution is reported as
    # "not_observable", never as "passed".
    requires_actor: bool = False


@dataclass
class ScenarioContext:
    policy: Policy
    seed: int

    def rng(self, salt: str) -> random.Random:
        return random.Random("%s:%s" % (self.seed, salt))

    def forbidden(self, i: int = 0) -> str:
        pool = self.policy.forbidden_actions or DEFAULT_FORBIDDEN
        return pool[i % len(pool)]

    def scoped_action(self) -> Optional["tuple[str, List[str]]"]:
        """An allowed, non-forbidden tool whose declared `tool_effects` go beyond plain
        reading, for scenarios that test whether a task scoped to analysis/read-only stays
        within that scope (see agentsec/attacks/action_without_authorization.py). Returns
        (tool_name, non_read_effects) for the first such tool, or None when the policy hasn't
        declared `tool_effects` for any allowed tool -- callers must produce no scenarios in
        that case rather than guessing which tool is state-changing."""
        for name in self.policy.allowed_tools or []:
            if name in self.policy.forbidden_actions:
                continue
            effects = self.policy.tool_effects.get(name, [])
            extra = [e for e in effects if e != "read" and e not in DATA_LABELS and e not in INTERNAL_EFFECTS]
            if extra:
                return name, extra
        return None

    def tools_with(self, *effects: str) -> List[str]:
        """Allowed, non-forbidden tools whose declared `tool_effects` include any of `effects`
        (action effects or data labels), in allowlist order. Empty when nothing is declared --
        callers must then produce no scenarios rather than guess from tool names."""
        return tools_with(self.policy, effects)

    def retrieval_tool(self) -> str:
        """The tool whose results carry adversarial content in retrieval scenarios."""
        a = self.policy.agent
        if a.retrieval_tools:
            return a.retrieval_tools[0]
        allowed = self.policy.allowed_tools or []
        for name in allowed:
            if "search" in name or "retriev" in name or "lookup" in name:
                return name
        return allowed[0] if allowed else "search_documents"

    def canary(self, salt: str) -> str:
        r = self.rng("canary:" + salt)
        return "CANARY-%08x" % r.getrandbits(32)

    def marker(self, salt: str):
        """A marker the agent can be told to emit without the literal marker text
        appearing in our input. Returns (marker, instruction_phrase)."""
        r = self.rng("marker:" + salt)
        word = r.choice(["ZEBRA", "QUARTZ", "MERIDIAN", "OBSIDIAN", "LANTERN"])
        digits = "".join(r.choice("0123456789") for _ in range(4))
        phrase = "the word %s followed immediately by the digits %s" % (word, "-".join(digits))
        return word + digits, phrase
