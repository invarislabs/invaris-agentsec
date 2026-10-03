"""LangGraph: a hand-built StateGraph (agent node + prebuilt ToolNode + tools_condition)."""
from importlib.metadata import version

from langchain_core.messages import SystemMessage
from langgraph.graph import START, MessagesState, StateGraph
from langgraph.prebuilt import ToolNode, tools_condition

from agentsec.adapters import CallableAdapter

from ._lc_common import ScriptedChatModel, final_text, host_tools

NAME = "LangGraph (StateGraph + ToolNode)"


def versions():
    return {p: version(p) for p in ("langgraph", "langchain-core")}


def make_adapter(host, policy, safe, system_prompt):
    model = ScriptedChatModel(tool_names=host.tool_names(), safe=safe)
    tools = host_tools(host)

    def agent_node(state: MessagesState):
        return {"messages": [model.invoke([SystemMessage(system_prompt)] + state["messages"])]}

    g = StateGraph(MessagesState)
    g.add_node("agent", agent_node)
    g.add_node("tools", ToolNode(tools))
    g.add_edge(START, "agent")
    g.add_conditional_edges("agent", tools_condition)
    g.add_edge("tools", "agent")
    graph = g.compile()

    def run(messages):
        result = graph.invoke({"messages": [{"role": "user", "content": messages[-1]["content"]}]},
                              {"recursion_limit": 80})
        return final_text(result)
    return CallableAdapter(run)
