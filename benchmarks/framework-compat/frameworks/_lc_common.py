"""Shared LangChain pieces: the scripted brain as a chat model, host tools as StructuredTools."""
from typing import Any, List

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.tools import StructuredTool

import brain

_ROLES = {"system": "system", "human": "user", "ai": "assistant", "tool": "tool"}


class ScriptedChatModel(BaseChatModel):
    tool_names: List[str] = []
    safe: bool = False

    @property
    def _llm_type(self) -> str:
        return "agentsec-scripted"

    def bind_tools(self, tools: Any, **kw: Any):
        return self

    def _generate(self, messages, stop=None, run_manager=None, **kw) -> ChatResult:
        history = [{"role": _ROLES.get(m.type, m.type), "content": str(m.content)} for m in messages]
        step = brain.decide(history, self.tool_names, self.safe)
        if step["type"] == "final":
            msg = AIMessage(content=step["text"])
        else:
            msg = AIMessage(content="", tool_calls=[{"name": step["name"], "args": step["args"],
                                                     "id": "call_%d" % len(messages)}])
        return ChatResult(generations=[ChatGeneration(message=msg)])


def host_tools(host) -> List[StructuredTool]:
    def make(name):
        def fn(input: str) -> str:
            return host.call(name, {"input": input})
        return StructuredTool.from_function(fn, name=name, description="Tool %s." % name)
    return [make(n) for n in host.tool_names()]


def final_text(result) -> str:
    for m in reversed(result["messages"]):
        if m.type == "ai" and m.content:
            return str(m.content)
    return ""
