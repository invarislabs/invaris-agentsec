"""CrewAI team: planner, researcher and executor agents in one Crew, delegating with CrewAI's own
built-in "Delegate work to coworker" tool (allow_delegation=True).

CrewAI runs the delegation internally, so AgentSec cannot see it through its tools. Attribution
comes from a small instrumentation hook instead: `DelegateWorkTool._run` is wrapped so each
hand-off is recorded on AgentSec's host (actor = the delegating agent) and a stack of active agents
is kept, from which every host tool call gets its `actor` and `delegated_by`. (CrewAI's event bus
was not used: it dispatches sync handlers on a thread pool, so events can arrive after the
delegated agent has already acted.)

Modes:
  vulnerable           the planner owns the task and delegates; the researcher is over-provisioned
                       with `apply_change` and has allow_delegation=True.
  vulnerable_research_led
                       the researcher owns the task (one agent per task, a common crew layout) with
                       allow_delegation=True, so it can hand work to the executor itself.
  safe                 only the planner delegates; the researcher has only `search_docs`.

Observed CrewAI behavior (1.15): an agent that is *delegated* work runs with its own tools only --
CrewAI does not give it delegation tools, even with allow_delegation=True -- so a delegated
researcher cannot chain a hand-off to the executor. Peer delegation needs the researcher to own a
task, which is what `vulnerable_research_led` sets up.
"""
import json
import os
import sys
from importlib.metadata import version
from typing import Type

os.environ.setdefault("CREWAI_DISABLE_TELEMETRY", "true")
os.environ.setdefault("OTEL_SDK_DISABLED", "true")
os.environ.setdefault("CREWAI_TRACING_ENABLED", "false")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crewai import Agent, Crew, Process, Task  # noqa: E402
from crewai.llms.base_llm import BaseLLM  # noqa: E402
from crewai.tools import BaseTool  # noqa: E402
from crewai.tools.agent_tools.delegate_work_tool import DelegateWorkTool  # noqa: E402
from pydantic import BaseModel, Field  # noqa: E402

from agentsec.adapters import CallableAdapter  # noqa: E402

import brain  # noqa: E402

NAME = "CrewAI (crew with built-in delegation)"
MODES = {"vulnerable": {"safe": False}, "vulnerable_research_led": {"safe": False, "research_led": True},
         "safe": {"safe": True}}
DELEGATE = "delegate_work_to_coworker"
STACK = []          # active agents, outermost first
HOST = {}


def versions():
    return {"crewai": version("crewai")}


def _delegated_by(actor):
    return STACK[-2] if len(STACK) >= 2 and STACK[-1] == actor else None


_original_run = DelegateWorkTool._run


def _instrumented_run(self, task, context, coworker=None, **kw):
    host = HOST["host"]
    delegator = STACK[-1] if STACK else "planner"
    target = (coworker or "").strip().lower()
    host.call(target, {"task": task, "context": context}, actor=delegator, delegated_by=_delegated_by(delegator))
    STACK.append(target)
    try:
        return _original_run(self, task, context, coworker, **kw)
    finally:
        STACK.pop()


DelegateWorkTool._run = _instrumented_run


class TeamLLM(BaseLLM):
    tool_names: list = []
    coworkers: list = []
    safe: bool = False

    def supports_function_calling(self) -> bool:
        return True

    def call(self, messages, tools=None, callbacks=None, available_functions=None, from_task=None,
             from_agent=None, response_model=None, **kw):
        msgs = [{"role": "user", "content": messages}] if isinstance(messages, str) else messages
        history = [{"role": m.get("role", "user"), "content": str(m.get("content") or "")} for m in msgs]
        offered = [t["function"]["name"] for t in tools or [] if isinstance(t, dict) and "function" in t]
        names = [n for n in self.tool_names if n in offered] + (self.coworkers if DELEGATE in offered else [])
        step = brain.decide(history, names, self.safe)
        if step["type"] == "final" or not tools:
            return step.get("text") or "Done."
        if step["name"] in self.coworkers:
            name, args = DELEGATE, {"task": step["args"]["input"], "context": step["args"]["input"],
                                    "coworker": step["name"]}
        else:
            name, args = step["name"], step["args"]
        return [{"id": "call_%d" % len(msgs), "type": "function",
                 "function": {"name": name, "arguments": json.dumps(args)}}]


class _Input(BaseModel):
    input: str = Field(description="Input for the tool.")


def _tool(host, tool_name, actor):
    class HostTool(BaseTool):
        name: str = tool_name
        description: str = "Tool %s." % tool_name
        args_schema: Type[BaseModel] = _Input

        def _run(self, input: str) -> str:
            return host.call(tool_name, {"input": input}, actor=actor, delegated_by=_delegated_by(actor))
    return HostTool()


def make_adapter(host, policy, safe, system_prompt, research_led=False):
    HOST["host"] = host

    def agent(role, tools, coworkers, delegate):
        llm = TeamLLM(model="agentsec-scripted", tool_names=[t.name for t in tools], coworkers=coworkers, safe=safe)
        return Agent(role=role, goal="Do your part of the team's work.", backstory="You are the %s." % role,
                     llm=llm, tools=tools, allow_delegation=delegate, max_iter=10, verbose=False)

    def run(messages):
        researcher_tools = [_tool(host, "search_docs", "researcher")]
        if not safe and not research_led:
            researcher_tools.append(_tool(host, "apply_change", "researcher"))
        planner = agent("planner", [], ["researcher", "executor"], True)
        researcher = agent("researcher", researcher_tools, [] if safe else ["executor"], not safe)
        executor = agent("executor", [_tool(host, "apply_change", "executor")], [], False)
        owner = researcher if research_led else planner
        task = Task(description=messages[-1]["content"], expected_output="An answer for the user.", agent=owner)
        STACK[:] = [owner.role]
        result = Crew(agents=[planner, researcher, executor], tasks=[task], process=Process.sequential,
                      verbose=False).kickoff()
        return str(result.raw)
    return CallableAdapter(run)
