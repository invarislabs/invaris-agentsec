"""Google ADK: an LlmAgent with function tools, run through InMemoryRunner and a custom BaseLlm."""
import asyncio
import os
from importlib.metadata import version
from typing import AsyncGenerator

os.environ.setdefault("ADK_DISABLE_TELEMETRY", "1")

from google.adk.agents import LlmAgent  # noqa: E402
from google.adk.models.base_llm import BaseLlm  # noqa: E402
from google.adk.models.llm_request import LlmRequest  # noqa: E402
from google.adk.models.llm_response import LlmResponse  # noqa: E402
from google.adk.runners import InMemoryRunner  # noqa: E402
from google.genai import types  # noqa: E402

from agentsec.adapters import CallableAdapter  # noqa: E402

import brain  # noqa: E402

NAME = "Google ADK (LlmAgent + InMemoryRunner)"


def versions():
    return {p: version(p) for p in ("google-adk", "google-genai")}


def _history(req: LlmRequest) -> list:
    out = []
    si = req.config.system_instruction if req.config else None
    if si:
        out.append({"role": "system", "content": si if isinstance(si, str) else str(si)})
    for c in req.contents or []:
        for p in c.parts or []:
            if p.function_response is not None:
                resp = p.function_response.response or {}
                out.append({"role": "tool", "content": str(resp.get("result", resp))})
            elif p.function_call is not None:
                out.append({"role": "assistant", "content": ""})
            elif p.text:
                out.append({"role": "user" if c.role == "user" else "assistant", "content": p.text})
    return out


class ScriptedLlm(BaseLlm):
    tool_names: list = []
    safe: bool = False

    async def generate_content_async(self, llm_request: LlmRequest, stream: bool = False
                                     ) -> AsyncGenerator[LlmResponse, None]:
        step = brain.decide(_history(llm_request), self.tool_names, self.safe)
        if step["type"] == "final":
            part = types.Part(text=step["text"])
        else:
            part = types.Part(function_call=types.FunctionCall(name=step["name"], args=step["args"]))
        yield LlmResponse(content=types.Content(role="model", parts=[part]))


def _tool(host, name):
    def fn(input: str) -> str:
        return host.call(name, {"input": input})
    fn.__name__ = name
    fn.__doc__ = "Tool %s.\n\nArgs:\n  input: input for the tool." % name
    return fn


def make_adapter(host, policy, safe, system_prompt):
    names = host.tool_names()

    async def go(text):
        agent = LlmAgent(name="assistant", model=ScriptedLlm(model="agentsec-scripted", tool_names=names, safe=safe),
                         instruction=system_prompt, tools=[_tool(host, n) for n in names])
        runner = InMemoryRunner(agent=agent, app_name="agentsec_bench")
        session = await runner.session_service.create_session(app_name="agentsec_bench", user_id="u")
        final = ""
        async for ev in runner.run_async(user_id="u", session_id=session.id,
                                         new_message=types.Content(role="user", parts=[types.Part(text=text)])):
            if ev.content and ev.content.parts:
                texts = [p.text for p in ev.content.parts if p.text]
                if texts and ev.author == "assistant":
                    final = texts[-1]
        return final

    def run(messages):
        return asyncio.run(go(messages[-1]["content"]))
    return CallableAdapter(run)
