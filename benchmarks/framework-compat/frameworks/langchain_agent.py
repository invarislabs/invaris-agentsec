"""LangChain v1 `langchain.agents.create_agent` (the LangGraph-based agent loop)."""
from importlib.metadata import version

from langchain.agents import create_agent

from agentsec.adapters import CallableAdapter

from ._lc_common import ScriptedChatModel, final_text, host_tools

NAME = "LangChain (create_agent)"


def versions():
    return {p: version(p) for p in ("langchain", "langchain-core", "langgraph")}


def make_adapter(host, policy, safe, system_prompt):
    model = ScriptedChatModel(tool_names=host.tool_names(), safe=safe)
    agent = create_agent(model, host_tools(host), system_prompt=system_prompt)

    def run(messages):
        result = agent.invoke({"messages": [{"role": "user", "content": messages[-1]["content"]}]},
                              {"recursion_limit": 80})
        return final_text(result)
    return CallableAdapter(run)
