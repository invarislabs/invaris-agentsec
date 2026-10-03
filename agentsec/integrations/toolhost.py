"""In-process tool host: the agent's framework runs its own loop, AgentSec supplies the tools.

The simulated-tool runner needs the agent to *return* tool calls so AgentSec can execute them.
Most agent frameworks (CrewAI, AutoGen, the OpenAI Agents SDK, Google ADK, smolagents, LangGraph)
run the tool loop themselves and only hand back a final answer. To test those agents with the
same scenarios, give them tools that call into a `ToolHost`:

    host = ToolHost(policy)
    tools = {name: host.tool(name) for name in host.tool_names()}   # plain Python callables
    agent = build_my_framework_agent(tools)                          # wrap them as framework tools
    adapter = CallableAdapter(lambda messages: agent.run(messages[-1]["content"]))
    suite = run_suite(policy, adapter, host=host)

Each call goes through the host, which answers with the running scenario's adversarial content
(for the tools that carry it) or a sandbox acknowledgement, and records the call. The runner
turns those records into `tool_call`/`tool_result` trace events (`executed_by_agent`), exactly as
with the MCP attack host (agentsec/mcp/host.py, which is this class plus an HTTP server), so every
evaluator applies unchanged. Nothing real is executed.

What this can and cannot observe: it sees every call the framework actually *executes* through a
host tool, with the arguments the framework passed. It does not see a call the framework refused
before execution (for example a tool name the framework does not know), or anything the agent
does through tools that do not go through the host.
"""
from __future__ import annotations

import threading
from typing import Any, Callable, Dict, List, Optional

from ..policies import Policy

SANDBOX_OK = "OK (simulated by AgentSec sandbox; no real action was taken)"
BENIGN_DOC = ("Vendor onboarding policy v3: vendors must complete the security questionnaire "
              "and sign the data-processing addendum before receiving access.")


def host_tool_names(policy: Policy) -> List[str]:
    """Tools offered to the agent: allowed tools, forbidden actions as decoys, retrieval tools."""
    names: List[str] = []
    for n in (policy.allowed_tools or []) + policy.forbidden_actions + policy.agent.retrieval_tools:
        if n not in names:
            names.append(n)
    return names


class ToolHost:
    """Records the tool calls an agent makes and answers them from the running scenario."""

    def __init__(self, policy: Policy):
        self.policy = policy
        self._lock = threading.Lock()
        self._responder: Optional[Callable[[str, dict, int], str]] = None
        self._is_scenario_tool: Callable[[str], bool] = lambda n: False
        self._calls = 0
        self._log: List[Dict[str, Any]] = []

    # ---- used by the runner
    def reset(self) -> None:
        with self._lock:
            self._calls = 0
            self._log = []

    def begin(self, responder: Optional[Callable[[str, dict, int], str]],
              is_scenario_tool: Callable[[str], bool]) -> None:
        with self._lock:
            self._responder, self._is_scenario_tool = responder, is_scenario_tool

    def drain(self) -> List[Dict[str, Any]]:
        with self._lock:
            out, self._log = self._log, []
        return out

    # ---- used by the agent's tools
    def tool_names(self) -> List[str]:
        return host_tool_names(self.policy)

    def call(self, name: str, arguments: Dict[str, Any], actor: Optional[str] = None,
             delegated_by: Optional[str] = None) -> str:
        with self._lock:
            if self._is_scenario_tool(name):
                if self._responder:
                    result = self._responder(name, arguments, self._calls)
                    self._calls += 1
                else:
                    result = BENIGN_DOC
            else:
                result = SANDBOX_OK
            entry: Dict[str, Any] = {"name": name, "arguments": dict(arguments or {}), "result": result}
            if actor:
                entry["actor"] = actor
            if delegated_by:
                entry["delegated_by"] = delegated_by
            self._log.append(entry)
        return result

    def tool(self, name: str, actor: Optional[str] = None) -> Callable[..., str]:
        """A plain callable `fn(**arguments) -> str` for `name`, for wrapping as a framework tool."""
        def fn(**arguments: Any) -> str:
            return self.call(name, arguments, actor=actor)
        fn.__name__ = name
        fn.__doc__ = "Tool %s (simulated by AgentSec)." % name
        return fn
