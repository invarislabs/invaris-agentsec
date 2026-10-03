"""OpenAI Agents SDK team: a planner whose tools are its sub-agents (the SDK's agents-as-tools
pattern, Runner.run on a nested Agent), each sub-agent with its own tools.

Attribution comes from topology, not from the framework: every tool instance is bound to the
agent that owns it (`actor`) and to the agent that can reach that owner (`delegated_by`), so a
call through it is attributed without any framework hook. Delegation tools record the hand-off on
AgentSec's host before running the sub-agent.

Vulnerable team: the researcher is over-provisioned (it also has `apply_change`) and may ask the
executor directly (peer delegation, like CrewAI's allow_delegation). Safe team: the researcher has
only `search_docs` and no teammates to call.
"""
import json
import os
import sys
from importlib.metadata import version

os.environ.setdefault("OPENAI_AGENTS_DISABLE_TRACING", "1")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents import Agent, FunctionTool, RunConfig, Runner  # noqa: E402
from agents.exceptions import MaxTurnsExceeded  # noqa: E402

from agentsec.adapters import CallableAdapter  # noqa: E402

from frameworks.openai_agents_sdk import ScriptedModel  # noqa: E402

NAME = "OpenAI Agents SDK (agents as tools)"
SCHEMA = {"type": "object", "properties": {"input": {"type": "string"}}, "required": ["input"],
          "additionalProperties": False}


def versions():
    return {p: version(p) for p in ("openai-agents", "openai")}


def _host_tool(host, name, actor, by):
    async def invoke(ctx, args_json):
        return host.call(name, json.loads(args_json or "{}"), actor=actor, delegated_by=by)
    return FunctionTool(name=name, description="Tool %s." % name, params_json_schema=SCHEMA, on_invoke_tool=invoke)


def _delegate_tool(host, target_name, target_agent, caller, caller_parent):
    async def invoke(ctx, args_json):
        args = json.loads(args_json or "{}")
        host.call(target_name, args, actor=caller, delegated_by=caller_parent)   # the hand-off itself
        try:
            result = await Runner.run(target_agent, args.get("input", ""), max_turns=15,
                                      run_config=RunConfig(tracing_disabled=True))
            return str(result.final_output)
        except MaxTurnsExceeded:
            return "%s stopped at its turn limit." % target_name
    return FunctionTool(name=target_name, description="Ask the %s agent to do something." % target_name,
                        params_json_schema=SCHEMA, on_invoke_tool=invoke)


def _agent(name, tools, safe, instructions=""):
    return Agent(name=name, instructions=instructions or "You are the %s." % name, tools=tools,
                 model=ScriptedModel([t.name for t in tools], safe))


def build_team(host, safe, system_prompt):
    def executor(parent):
        return _agent("executor", [_host_tool(host, "apply_change", "executor", parent)], safe)

    researcher_tools = [_host_tool(host, "search_docs", "researcher", "planner")]
    if not safe:
        researcher_tools.append(_host_tool(host, "apply_change", "researcher", "planner"))      # over-provisioned
        researcher_tools.append(_delegate_tool(host, "executor", executor("researcher"), "researcher", "planner"))
    researcher = _agent("researcher", researcher_tools, safe)
    return _agent("planner", [_delegate_tool(host, "researcher", researcher, "planner", None),
                              _delegate_tool(host, "executor", executor("planner"), "planner", None)],
                  safe, system_prompt)


def make_adapter(host, policy, safe, system_prompt):  # noqa: D103
    def run(messages):
        planner = build_team(host, safe, system_prompt)
        try:
            result = Runner.run_sync(planner, messages[-1]["content"], max_turns=20,
                                     run_config=RunConfig(tracing_disabled=True))
        except MaxTurnsExceeded:
            return "Stopped at the turn limit."
        return str(result.final_output)
    return CallableAdapter(run)
