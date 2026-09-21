"""Adapter for in-process agents: wrap any Python function as the agent under test.

Use it to test an agent built with any framework without running an HTTP server. You write the small
function that calls your agent; AgentSec does not import or depend on any framework.
"""
from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

from .base import AdapterError, AgentAdapter, AgentReply, ToolCall


class CallableAdapter(AgentAdapter):
    """`fn(messages, tools, session)` may return:

    * a string (the agent's final answer),
    * an `AgentReply`, or
    * a dict: {"content": str, "tool_calls": [{"name", "arguments", "id"?}],
               "executed": [{"name", "arguments", "result"}], "cost_usd": float,
               "prompt_tokens": int, "completion_tokens": int}

    `fn` may take just `(messages)`, `(messages, tools)` or all three; extra parameters are
    passed only if it accepts them.
    """

    def __init__(self, fn: Callable[..., Any]):
        self.fn = fn

    def chat(self, messages: List[Dict[str, Any]], tools: List[Dict[str, Any]],
             session: Optional[str] = None) -> AgentReply:
        try:
            try:
                result = self.fn(messages, tools, session)
            except TypeError as exc:
                if "positional argument" not in str(exc):
                    raise
                try:
                    result = self.fn(messages, tools)
                except TypeError as exc2:
                    if "positional argument" not in str(exc2):
                        raise
                    result = self.fn(messages)
        except AdapterError:
            raise
        except Exception as exc:  # the agent crashed: report it as an adapter error for this scenario
            raise AdapterError("agent function raised %s: %s" % (type(exc).__name__, exc))
        return self._to_reply(result)

    @staticmethod
    def _to_reply(result: Any) -> AgentReply:
        if isinstance(result, AgentReply):
            return result
        if isinstance(result, str):
            return AgentReply(content=result)
        if not isinstance(result, dict):
            raise AdapterError("agent function must return a string, dict or AgentReply, got %s"
                               % type(result).__name__)
        reply = AgentReply(content=result.get("content"))
        for i, tc in enumerate(result.get("tool_calls") or []):
            if not tc.get("name"):
                raise AdapterError("tool call without a name")
            args = tc.get("arguments") or {}
            reply.tool_calls.append(ToolCall(tc.get("id") or "call_%d" % i, tc["name"],
                                             args if isinstance(args, dict) else {"_raw": args}))
        reply.executed = [e for e in (result.get("executed") or []) if isinstance(e, dict) and e.get("name")]
        reply.prompt_tokens = int(result.get("prompt_tokens") or 0)
        reply.completion_tokens = int(result.get("completion_tokens") or 0)
        cost = result.get("cost_usd")
        reply.cost_usd = float(cost) if isinstance(cost, (int, float)) else None
        return reply
