"""Adapter for LangChain and LangGraph agents.

Works with anything that has `.invoke(input, config)`:

* LangGraph agents and graphs whose state has a `messages` list
  (`langgraph.prebuilt.create_react_agent`, `langchain.agents.create_agent`, or your own `StateGraph`).
* LangChain `AgentExecutor`s, which take `{"input": ...}` and return `{"output": ..., "intermediate_steps": [...]}`.

The framework runs the agent's own tools, so AgentSec sees the calls the agent actually made
(read from the returned messages or intermediate steps) rather than simulating them. The tools should
therefore be sandboxed test doubles: a `send_email` tool in a test agent should not send real mail.
Use `declare_tools: false` in the policy, because the agent already has its tools.

This module duck-types the framework; it does not import langchain or langgraph.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from ..adapters.base import AdapterError, AgentAdapter, AgentReply


def _text(content: Any) -> str:
    """Message content is a string or a list of content blocks."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, str):
                parts.append(block)
            elif isinstance(block, dict) and block.get("type") in (None, "text"):
                parts.append(str(block.get("text", "")))
        return "".join(parts)
    return "" if content is None else str(content)


def _kind(msg: Any) -> str:
    return str(getattr(msg, "type", None) or (msg.get("type") or msg.get("role") if isinstance(msg, dict) else ""))


def _get(msg: Any, key: str, default: Any = None) -> Any:
    return msg.get(key, default) if isinstance(msg, dict) else getattr(msg, key, default)


class LangChainAdapter(AgentAdapter):
    """`LangChainAdapter(agent, use_session_as_thread=True)`.

    With `use_session_as_thread`, AgentSec's session id is passed as `config["configurable"]["thread_id"]`,
    which is how LangGraph checkpointers key memory. Memory-poisoning scenarios need this.
    """

    def __init__(self, agent: Any, use_session_as_thread: bool = True):
        if not hasattr(agent, "invoke"):
            raise TypeError("agent must have an .invoke() method (a LangChain runnable or LangGraph graph)")
        self.agent = agent
        self.use_session_as_thread = use_session_as_thread

    def chat(self, messages: List[Dict[str, Any]], tools: List[Dict[str, Any]],
             session: Optional[str] = None) -> AgentReply:
        config: Dict[str, Any] = {}
        if session and self.use_session_as_thread:
            config = {"configurable": {"thread_id": session}}
        user = next((m["content"] for m in reversed(messages) if m.get("role") == "user"), "")
        # A checkpointed graph already holds earlier turns for this thread, so send only the new user turn.
        payloads = [{"messages": [{"role": "user", "content": user}]}, {"input": user}]
        last_error: Optional[Exception] = None
        result: Any = None
        for payload in payloads:
            try:
                result = self.agent.invoke(payload, config) if config else self.agent.invoke(payload)
                break
            except (KeyError, TypeError, ValueError) as exc:   # wrong input shape for this agent: try the next
                last_error = exc
                continue
            except Exception as exc:
                raise AdapterError("agent raised %s: %s" % (type(exc).__name__, exc))
        else:
            raise AdapterError("could not invoke the agent with {'messages': [...]} or {'input': ...}: %s" % last_error)
        return self._parse(result)

    def _parse(self, result: Any) -> AgentReply:
        if not isinstance(result, dict):
            raise AdapterError("agent returned %s, expected a dict with `messages` or `output`" % type(result).__name__)
        reply = AgentReply()
        if isinstance(result.get("messages"), list):
            self._from_messages(result["messages"], reply)
        elif "output" in result:
            reply.content = _text(result["output"])
            for step in result.get("intermediate_steps") or []:
                try:
                    action, observation = step
                except (TypeError, ValueError):
                    continue
                args = _get(action, "tool_input", {})
                reply.executed.append({"name": _get(action, "tool", "unknown"),
                                       "arguments": args if isinstance(args, dict) else {"input": args},
                                       "result": _text(observation)})
        else:
            raise AdapterError("agent result has neither `messages` nor `output` (keys: %s)"
                               % ", ".join(sorted(result)))
        return reply

    @staticmethod
    def _from_messages(all_messages: List[Any], reply: AgentReply) -> None:
        last_human = max((i for i, m in enumerate(all_messages) if _kind(m) in ("human", "user")), default=-1)
        new = all_messages[last_human + 1:]
        results: Dict[str, str] = {}
        for m in new:
            if _kind(m) == "tool":
                results[str(_get(m, "tool_call_id", ""))] = _text(_get(m, "content"))
        final: Optional[str] = None
        for m in new:
            kind = _kind(m)
            if kind not in ("ai", "assistant"):
                continue
            usage = _get(m, "usage_metadata") or {}
            reply.prompt_tokens += int(usage.get("input_tokens") or 0)
            reply.completion_tokens += int(usage.get("output_tokens") or 0)
            for tc in _get(m, "tool_calls") or []:
                args = tc.get("args") if isinstance(tc, dict) else getattr(tc, "args", {})
                if isinstance(args, str):
                    try:
                        args = json.loads(args)
                    except ValueError:
                        args = {"_raw": args}
                tid = str(tc.get("id") if isinstance(tc, dict) else getattr(tc, "id", ""))
                reply.executed.append({"name": tc.get("name") if isinstance(tc, dict) else getattr(tc, "name"),
                                       "arguments": args if isinstance(args, dict) else {"_raw": args},
                                       "result": results.get(tid)})
            text = _text(_get(m, "content"))
            if text:
                final = text
        reply.content = final or ""
