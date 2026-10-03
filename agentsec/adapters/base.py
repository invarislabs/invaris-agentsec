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
    # Multi-agent systems: which agent made this call, and which agent delegated the work to it.
    # Optional; single-agent systems leave both unset. Recorded on the trace event's meta.
    actor: Optional[str] = None
    delegated_by: Optional[str] = None


@dataclass
class AgentReply:
    content: Optional[str] = None
    tool_calls: List[ToolCall] = field(default_factory=list)
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cost_usd: Optional[float] = None
    # Tool calls the agent executed itself (server-side) and reported via the
    # `x_agentsec.events` extension: [{"name", "arguments", "result", "actor"?, "delegated_by"?}].
    executed: List[Dict[str, Any]] = field(default_factory=list)
    # Multi-agent systems: which agent wrote `content` (see ToolCall.actor).
    actor: Optional[str] = None


class AgentAdapter:
    """Connects AgentSec to an agent. Implementations must not keep conversation state:
    the runner resends the full conversation on every step."""

    def chat(self, messages: List[Dict[str, Any]], tools: List[Dict[str, Any]],
             session: Optional[str] = None) -> AgentReply:
        """`session` identifies one simulated user. It stays the same across the
        conversations of a multi-session scenario (memory tests) and is unique per run.
        Agents without memory can ignore it."""
        raise NotImplementedError
