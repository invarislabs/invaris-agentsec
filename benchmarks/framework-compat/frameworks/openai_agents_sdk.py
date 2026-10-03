"""OpenAI Agents SDK: an Agent with function tools, run with `Runner.run_sync` and a custom Model."""
import json
import os
from importlib.metadata import version

os.environ.setdefault("OPENAI_AGENTS_DISABLE_TRACING", "1")

from agents import Agent, FunctionTool, ModelSettings, RunConfig, Runner  # noqa: E402
from agents.exceptions import MaxTurnsExceeded  # noqa: E402
from agents.items import ModelResponse  # noqa: E402
from agents.models.interface import Model  # noqa: E402
from agents.usage import Usage  # noqa: E402
from openai.types.responses import ResponseFunctionToolCall, ResponseOutputMessage, ResponseOutputText  # noqa: E402

from agentsec.adapters import CallableAdapter  # noqa: E402

import brain  # noqa: E402

NAME = "OpenAI Agents SDK (Agent + Runner)"


def versions():
    return {p: version(p) for p in ("openai-agents", "openai")}


def _history(system, items):
    out = [{"role": "system", "content": system or ""}]
    for it in ([{"role": "user", "content": items}] if isinstance(items, str) else items):
        it = it if isinstance(it, dict) else it.model_dump()
        kind = it.get("type")
        if kind == "function_call_output":
            out.append({"role": "tool", "content": str(it.get("output", ""))})
        elif kind == "function_call":
            out.append({"role": "assistant", "content": ""})
        elif it.get("role") in ("user", "system", "developer"):
            c = it.get("content")
            text = c if isinstance(c, str) else " ".join(p.get("text", "") for p in c or [] if isinstance(p, dict))
            out.append({"role": "user" if it["role"] == "user" else "system", "content": text})
        elif it.get("role") == "assistant":
            out.append({"role": "assistant", "content": ""})
    return out


class ScriptedModel(Model):
    def __init__(self, tool_names, safe):
        self.tool_names, self.safe, self.n = tool_names, safe, 0

    async def get_response(self, system_instructions, input, model_settings, tools, output_schema, handoffs,
                           tracing, *, previous_response_id=None, conversation_id=None, prompt=None):
        step = brain.decide(_history(system_instructions, input), self.tool_names, self.safe)
        self.n += 1
        if step["type"] == "final":
            item = ResponseOutputMessage(id="msg_%d" % self.n, type="message", role="assistant", status="completed",
                                         content=[ResponseOutputText(type="output_text", text=step["text"],
                                                                     annotations=[])])
        else:
            item = ResponseFunctionToolCall(type="function_call", id="fc_%d" % self.n, call_id="call_%d" % self.n,
                                            name=step["name"], arguments=json.dumps(step["args"]))
        return ModelResponse(output=[item], usage=Usage(), response_id=None)

    def stream_response(self, *a, **kw):
        raise NotImplementedError


def _tool(host, name):
    async def invoke(ctx, args_json: str) -> str:
        args = json.loads(args_json or "{}")
        return host.call(name, args)
    return FunctionTool(name=name, description="Tool %s." % name,
                        params_json_schema={"type": "object", "properties": {"input": {"type": "string"}},
                                            "required": ["input"], "additionalProperties": False},
                        on_invoke_tool=invoke, strict_json_schema=True)


def make_adapter(host, policy, safe, system_prompt):
    names = host.tool_names()

    def run(messages):
        agent = Agent(name="assistant", instructions=system_prompt, tools=[_tool(host, n) for n in names],
                      model=ScriptedModel(names, safe), model_settings=ModelSettings())
        try:
            result = Runner.run_sync(agent, messages[-1]["content"], max_turns=40,
                                     run_config=RunConfig(tracing_disabled=True))
        except MaxTurnsExceeded:
            return "Stopped: the agent reached its turn limit."
        return str(result.final_output)
    return CallableAdapter(run)
