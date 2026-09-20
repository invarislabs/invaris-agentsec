from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


class AdapterError(RuntimeError):
    """The agent under test could not be reached or returned an unusable reply."""


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: Dict[str, Any]


@dataclass
class AgentReply:
    content: Optional[str] = None
    tool_calls: List[ToolCall] = field(default_factory=list)
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cost_usd: Optional[float] = None
    # Tool calls the agent executed itself (server-side) and reported via the
    # `x_agentsec.events` extension: [{"name", "arguments", "result"}].
    executed: List[Dict[str, Any]] = field(default_factory=list)


class AgentAdapter:
    """Connects AgentSec to an agent. Implementations must be stateless per call:
    the runner resends the full conversation on every step."""

    def chat(self, messages: List[Dict[str, Any]], tools: List[Dict[str, Any]]) -> AgentReply:
        raise NotImplementedError
