# Testing agents built with frameworks

AgentSec talks to agents through adapters. Besides the OpenAI-compatible HTTP adapter, there are two ways to test an agent built with a framework, without exposing it over HTTP.

## LangChain and LangGraph

```python
from agentsec.api import AgentTarget, SecuritySuite
from agentsec.integrations import LangChainAdapter

agent = build_my_agent()          # a LangGraph graph / create_react_agent(...) / create_agent(...) / AgentExecutor

target = AgentTarget("http://in-process",          # placeholder, never contacted
                     allowed_tools=["search_documents"], forbidden_tools=["send_email"],
                     secrets=["sk-test-123"], declare_tools=False)
result = SecuritySuite(target, adapter=LangChainAdapter(agent)).run()
result.assert_clean(fail_on="high")
```

What the adapter does:

- Calls `agent.invoke({"messages": [...]})` (LangGraph) or `agent.invoke({"input": ...})` (`AgentExecutor`), whichever the agent accepts.
- Passes AgentSec's session id as `config["configurable"]["thread_id"]`, so a checkpointer keeps memory per simulated user. Memory-poisoning scenarios rely on this. Disable with `use_session_as_thread=False`.
- Reports the tool calls the agent **actually made** (read from the returned messages or `intermediate_steps`) as executed calls, so forbidden and unauthorized calls are detected. It also reads token usage from `usage_metadata` when present.
- Because the framework runs the tools, **tools must be sandboxed test doubles**. AgentSec does not simulate them here. A `send_email` tool in a test agent must not send real email.
- The adapter duck-types the framework and imports nothing from it.

Under the pytest plugin, build the target and adapter in your own fixture (the plugin's default fixtures use the HTTP adapter).

Limits: adversarial content reaches such an agent only through the user message and whatever your test doubles return. Scenarios that rely on AgentSec injecting content into tool results (tool-output poisoning, poisoned documents) need your test tools to return that content. To get AgentSec to deliver it, put your agent behind an MCP client and use [`--mcp-listen`](mcp-testing.md#testing-an-agent-that-uses-mcp---mcp-listen), or expose it over HTTP with tools declared.

Verified against real LangGraph (`create_react_agent`, with and without a checkpointer) using a scripted stand-in for the model, and a stub `AgentExecutor`-shaped result. Not verified against real LLM-backed agents, `AgentExecutor` itself, or other LangChain versions than the one in CI.

## Any other framework

Wrap a function with `CallableAdapter` (see [Python API](python-api-and-pytest.md#testing-an-in-process-agent-no-http-server)): you write the few lines that call your agent (OpenAI Agents SDK, LlamaIndex, CrewAI, AutoGen, plain code) and return the answer and the tool calls it made. There are no other framework-specific integrations yet.

Two other routes work for any agent: expose it through an OpenAI-compatible HTTP endpoint (many frameworks and servers can do this), or make it use MCP servers and test it with [`--mcp-listen`](mcp-testing.md#testing-an-agent-that-uses-mcp---mcp-listen).
