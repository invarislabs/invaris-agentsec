"""AutoGen AgentChat: an AssistantAgent with FunctionTools (`agent.run(task=...)`)."""
import asyncio
import json
from importlib.metadata import version
from typing import Any, Mapping, Optional, Sequence

from autogen_agentchat.agents import AssistantAgent
from autogen_core import CancellationToken, FunctionCall
from autogen_core.models import (AssistantMessage, ChatCompletionClient, CreateResult, FunctionExecutionResultMessage,
                                 ModelInfo, RequestUsage, SystemMessage, UserMessage)
from autogen_core.tools import FunctionTool

from agentsec.adapters import CallableAdapter

import brain

NAME = "AutoGen AgentChat (AssistantAgent)"


def versions():
    return {p: version(p) for p in ("autogen-agentchat", "autogen-core")}


def _history(messages) -> list:
    out = []
    for m in messages:
        if isinstance(m, SystemMessage):
            out.append({"role": "system", "content": m.content})
        elif isinstance(m, UserMessage):
            out.append({"role": "user", "content": m.content if isinstance(m.content, str) else str(m.content)})
        elif isinstance(m, AssistantMessage):
            out.append({"role": "assistant", "content": m.content if isinstance(m.content, str) else ""})
        elif isinstance(m, FunctionExecutionResultMessage):
            for r in m.content:
                out.append({"role": "tool", "content": r.content})
    return out


class ScriptedClient(ChatCompletionClient):
    def __init__(self, tool_names, safe):
        self.tool_names, self.safe, self.n = tool_names, safe, 0

    async def create(self, messages: Sequence[Any], *, tools: Sequence[Any] = [], tool_choice: Any = "auto",
                     json_output: Optional[Any] = None, extra_create_args: Mapping[str, Any] = {},
                     cancellation_token: Optional[CancellationToken] = None) -> CreateResult:
        step = brain.decide(_history(messages), self.tool_names, self.safe)
        usage = RequestUsage(prompt_tokens=0, completion_tokens=0)
        if step["type"] == "final":
            return CreateResult(finish_reason="stop", content=step["text"], usage=usage, cached=False)
        self.n += 1
        call = FunctionCall(id="call_%d" % self.n, name=step["name"], arguments=json.dumps(step["args"]))
        return CreateResult(finish_reason="function_calls", content=[call], usage=usage, cached=False)

    def create_stream(self, *a, **kw):
        raise NotImplementedError

    async def close(self) -> None:
        pass

    def actual_usage(self) -> RequestUsage:
        return RequestUsage(prompt_tokens=0, completion_tokens=0)

    def total_usage(self) -> RequestUsage:
        return RequestUsage(prompt_tokens=0, completion_tokens=0)

    def count_tokens(self, messages, *, tools=[]) -> int:
        return 0

    def remaining_tokens(self, messages, *, tools=[]) -> int:
        return 100000

    @property
    def capabilities(self):
        return self.model_info

    @property
    def model_info(self) -> ModelInfo:
        return ModelInfo(vision=False, function_calling=True, json_output=False, family="unknown",
                         structured_output=False)


def _tool(host, name):
    def fn(input: str) -> str:
        return host.call(name, {"input": input})
    return FunctionTool(fn, description="Tool %s." % name, name=name)


def make_adapter(host, policy, safe, system_prompt):
    names = host.tool_names()

    def run(messages):
        agent = AssistantAgent("assistant", model_client=ScriptedClient(names, safe),
                               tools=[_tool(host, n) for n in names], system_message=system_prompt,
                               max_tool_iterations=25, reflect_on_tool_use=False)
        result = asyncio.run(agent.run(task=messages[-1]["content"]))
        texts = [m.content for m in result.messages if getattr(m, "type", "") == "TextMessage"
                 and getattr(m, "source", "") == "assistant"]
        if texts:
            return texts[-1]
        last = result.messages[-1]
        return last.content if isinstance(getattr(last, "content", None), str) else ""
    return CallableAdapter(run)
