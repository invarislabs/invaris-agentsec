"""CrewAI: one Agent with native function calling, one Task, one Crew (`crew.kickoff()`)."""
import json
import os
from importlib.metadata import version
from typing import Any, Type

os.environ.setdefault("CREWAI_DISABLE_TELEMETRY", "true")
os.environ.setdefault("OTEL_SDK_DISABLED", "true")
os.environ.setdefault("CREWAI_TRACING_ENABLED", "false")

from crewai import Agent, Crew, Task  # noqa: E402
from crewai.llms.base_llm import BaseLLM  # noqa: E402
from crewai.tools import BaseTool  # noqa: E402
from pydantic import BaseModel, Field  # noqa: E402

from agentsec.adapters import CallableAdapter  # noqa: E402

import brain  # noqa: E402

NAME = "CrewAI (Agent + Task + Crew)"


def versions():
    return {"crewai": version("crewai")}


class ScriptedLLM(BaseLLM):
    tool_names: list = []
    safe: bool = False

    def supports_function_calling(self) -> bool:
        return True

    def call(self, messages, tools=None, callbacks=None, available_functions=None, from_task=None,
             from_agent=None, response_model=None, **kw) -> Any:
        msgs = [{"role": "user", "content": messages}] if isinstance(messages, str) else messages
        history = [{"role": m.get("role", "user"), "content": str(m.get("content") or "")} for m in msgs]
        step = brain.decide(history, self.tool_names, self.safe)
        if step["type"] == "final":
            return step["text"]
        if not tools:
            # CrewAI asks for a plain-text answer (no tools offered) when max_iter is reached.
            return "I could not finish this task within the iteration limit."
        return [{"id": "call_%d" % len(msgs), "type": "function",
                 "function": {"name": step["name"], "arguments": json.dumps(step["args"])}}]


class _Input(BaseModel):
    input: str = Field(description="Input for the tool.")


def _tool(host, tool_name: str) -> BaseTool:
    class HostTool(BaseTool):
        name: str = tool_name
        description: str = "Tool %s." % tool_name
        args_schema: Type[BaseModel] = _Input

        def _run(self, input: str) -> str:
            return host.call(tool_name, {"input": input})
    return HostTool()


def make_adapter(host, policy, safe, system_prompt):
    names = host.tool_names()

    def run(messages):
        llm = ScriptedLLM(model="agentsec-scripted", tool_names=names, safe=safe)
        agent = Agent(role="Assistant", goal="Help the user with their request.", backstory=system_prompt,
                      llm=llm, tools=[_tool(host, n) for n in names], allow_delegation=False,
                      max_iter=25, verbose=False)
        task = Task(description=messages[-1]["content"], expected_output="An answer for the user.", agent=agent)
        result = Crew(agents=[agent], tasks=[task], verbose=False).kickoff()
        return str(result.raw)
    return CallableAdapter(run)
