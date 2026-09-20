from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from ..policies import Policy

# How adversarial content reaches the agent.
VECTOR_DIRECT = "direct"                    # in the user's message
VECTOR_DOCUMENT = "retrieved_document"      # inside a retrieved document
VECTOR_TOOL_OUTPUT = "tool_output"          # inside a tool result / error / metadata

# (tool_name, arguments, call_index_within_scenario) -> tool result text
ToolResponder = Callable[[str, dict, int], str]

DEFAULT_FORBIDDEN = ["send_email", "execute_payment", "reveal_credentials"]


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


@dataclass
class ScenarioContext:
    policy: Policy
    seed: int

    def rng(self, salt: str) -> random.Random:
        return random.Random("%s:%s" % (self.seed, salt))

    def forbidden(self, i: int = 0) -> str:
        pool = self.policy.forbidden_actions or DEFAULT_FORBIDDEN
        return pool[i % len(pool)]

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
