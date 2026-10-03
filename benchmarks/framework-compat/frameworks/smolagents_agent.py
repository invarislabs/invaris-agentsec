"""smolagents: a ToolCallingAgent with Tool subclasses and a custom Model (`agent.run(task)`)."""
from importlib.metadata import version

from smolagents import Tool, ToolCallingAgent
from smolagents.models import ChatMessage, ChatMessageToolCall, ChatMessageToolCallFunction, MessageRole, Model

from agentsec.adapters import CallableAdapter

import brain

NAME = "smolagents (ToolCallingAgent)"


def versions():
    return {"smolagents": version("smolagents")}


def _text(content) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return " ".join(str(p.get("text", "")) for p in content if isinstance(p, dict))
    return "" if content is None else str(content)


def _history(messages) -> list:
    roles = {MessageRole.SYSTEM: "system", MessageRole.USER: "user", MessageRole.ASSISTANT: "assistant",
             MessageRole.TOOL_CALL: "assistant", MessageRole.TOOL_RESPONSE: "tool"}
    out = []
    for m in messages:
        role = m.role if isinstance(m, ChatMessage) else m.get("role")
        content = m.content if isinstance(m, ChatMessage) else m.get("content")
        out.append({"role": roles.get(role, str(role)), "content": _text(content)})
    return out


class ScriptedModel(Model):
    def __init__(self, tool_names, safe):
        super().__init__(model_id="agentsec-scripted")
        self.tool_names, self.safe, self.n = tool_names, safe, 0

    def generate(self, messages, stop_sequences=None, response_format=None, tools_to_call_from=None, **kw):
        step = brain.decide(_history(messages), self.tool_names, self.safe)
        self.n += 1
        if not tools_to_call_from:  # asked for a plain-text final answer (e.g. after max_steps)
            text = step["text"] if step["type"] == "final" else "I could not finish within the step limit."
            return ChatMessage(role=MessageRole.ASSISTANT, content=text)
        if step["type"] == "final":
            name, args = "final_answer", {"answer": step["text"]}
        else:
            name, args = step["name"], step["args"]
        call = ChatMessageToolCall(id="call_%d" % self.n, type="function",
                                   function=ChatMessageToolCallFunction(name=name, arguments=args))
        return ChatMessage(role=MessageRole.ASSISTANT, content="", tool_calls=[call])


def _tool(host, tool_name):
    class HostTool(Tool):
        name = tool_name
        description = "Tool %s." % tool_name
        inputs = {"input": {"type": "string", "description": "Input for the tool."}}
        output_type = "string"

        def forward(self, input: str) -> str:
            return host.call(tool_name, {"input": input})
    return HostTool()


def make_adapter(host, policy, safe, system_prompt):
    names = host.tool_names()

    def run(messages):
        agent = ToolCallingAgent(tools=[_tool(host, n) for n in names], model=ScriptedModel(names, safe),
                                 instructions=system_prompt, max_steps=25, verbosity_level=0)
        return str(agent.run(messages[-1]["content"]))
    return CallableAdapter(run)
