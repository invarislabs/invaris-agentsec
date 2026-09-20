"""Normalized agent execution trace (schema version 1).

A trace is an ordered list of events recorded while one scenario ran against the
agent under test. Evaluators only ever look at traces, never at the adapter, so
any agent that can be adapted into this shape can be tested.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

TRACE_SCHEMA_VERSION = "1"

EVENT_TYPES = (
    "user_message",       # input sent to the agent
    "assistant_message",  # text (and/or tool calls) produced by the agent
    "tool_call",          # tool invocation requested by the agent
    "tool_result",        # result returned by AgentSec's sandboxed tool executor
    "limit",              # a policy limit stopped the run
    "error",              # adapter or runner failure
)

OUTCOMES = ("completed", "limit_exceeded", "error")


@dataclass
class TraceEvent:
    seq: int
    type: str
    t_ms: int = 0
    content: Optional[str] = None
    tool_name: Optional[str] = None
    tool_call_id: Optional[str] = None
    arguments: Optional[Dict[str, Any]] = None
    meta: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"seq": self.seq, "type": self.type, "t_ms": self.t_ms}
        for key in ("content", "tool_name", "tool_call_id", "arguments"):
            value = getattr(self, key)
            if value is not None:
                d[key] = value
        if self.meta:
            d["meta"] = self.meta
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "TraceEvent":
        return cls(
            seq=d["seq"], type=d["type"], t_ms=d.get("t_ms", 0),
            content=d.get("content"), tool_name=d.get("tool_name"),
            tool_call_id=d.get("tool_call_id"), arguments=d.get("arguments"),
            meta=d.get("meta", {}),
        )


@dataclass
class Usage:
    steps: int = 0
    tool_calls: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    cost_usd: Optional[float] = None  # None = unknown

    def to_dict(self) -> Dict[str, Any]:
        return {
            "steps": self.steps, "tool_calls": self.tool_calls,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens, "cost_usd": self.cost_usd,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Usage":
        return cls(**{k: d.get(k, getattr(cls(), k)) for k in cls().__dict__})


@dataclass
class Trace:
    scenario_id: str
    events: List[TraceEvent] = field(default_factory=list)
    usage: Usage = field(default_factory=Usage)
    duration_s: float = 0.0
    outcome: str = "completed"
    limit: Optional[str] = None  # which limit stopped the run, if any
    error: Optional[str] = None
    schema_version: str = TRACE_SCHEMA_VERSION

    def add(self, type: str, t_ms: int = 0, **kwargs: Any) -> TraceEvent:
        if type not in EVENT_TYPES:
            raise ValueError("unknown trace event type: %r" % type)
        event = TraceEvent(seq=len(self.events), type=type, t_ms=t_ms, **kwargs)
        self.events.append(event)
        return event

    def of_type(self, *types: str) -> List[TraceEvent]:
        return [e for e in self.events if e.type in types]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "scenario_id": self.scenario_id,
            "outcome": self.outcome,
            "limit": self.limit,
            "error": self.error,
            "duration_s": round(self.duration_s, 3),
            "usage": self.usage.to_dict(),
            "events": [e.to_dict() for e in self.events],
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Trace":
        return cls(
            scenario_id=d["scenario_id"],
            events=[TraceEvent.from_dict(e) for e in d.get("events", [])],
            usage=Usage.from_dict(d.get("usage", {})),
            duration_s=d.get("duration_s", 0.0),
            outcome=d.get("outcome", "completed"),
            limit=d.get("limit"), error=d.get("error"),
            schema_version=d.get("schema_version", TRACE_SCHEMA_VERSION),
        )
