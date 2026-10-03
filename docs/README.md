# Invaris AgentSec documentation

These docs describe what is built today; see [What's Built](../README.md#whats-built) in the main README for the
full list. Planned work is in [Future Work](../README.md#future-work) and is not described here.

| Document | Read it to... |
|---|---|
| [Why AgentSec](why-agentsec.md) | See real, sourced incidents, adoption survey data, and institutional AI bans that motivate this project |
| [Getting started](getting-started.md) | Install AgentSec, run it against the bundled agent, read the output, use the CLI |
| [Architecture](architecture.md) | Understand how a run works, what each component does, and why it is designed this way |
| [Policy reference](policy-reference.md) | Write an `agentsec.yaml` for your own agent |
| [Attack catalog](attack-catalog.md) | See every scenario, what it simulates, and how a failure is detected |
| [Agent contract](agent-contract.md) | Make your agent testable, and understand the reference agent |
| [Reports and traces](reports-and-traces.md) | Use the JSON, HTML and Markdown reports, findings and the trace format |
| [OWASP mapping](owasp-mapping.md) | See how findings map to the OWASP Top 10 for Agentic Applications |
| [Judge (model-assisted checks)](judge.md) | Enable the optional judge model, and understand what it sends and reports |
| [Python API and pytest](python-api-and-pytest.md) | Run scenarios from code and from pytest |
| [Testing](testing.md) | Run the test suite, verify the engine by hand, add AgentSec to CI |
| [MCP testing](mcp-testing.md) | Scan an MCP server's tool definitions, or test an agent that uses MCP with `--mcp-listen` |
| [Frameworks](frameworks.md) | Test LangChain/LangGraph agents and other in-process agents |
| [Multi-agent testing](multi-agent.md) | Declare agent roles, report which agent acted, and test delegation and privilege escalation |
| [GitHub Actions](github-actions.md) | Use the packaged action in CI |
| [Extending](extending.md) | Add a scenario category, an evaluator or an adapter |
| [Domain attack packs](domain-attack-packs.md) | See all five reference attack packs: coding-agent, browser-agent, RAG, customer-support and on-chain agents |
| [Blog](blogs.md) | Posts from the people building AgentSec |

## What AgentSec does in one paragraph

AgentSec pretends to be a hostile environment around your agent. It sends the agent adversarial
user messages, and it answers the agent's tool calls with poisoned documents, poisoned tool output
and endless "retry" loops. It can also run two conversations in a row to see whether poisoned or private
information survives in the agent's memory. Every step is recorded as a normalized trace. Deterministic evaluators
then check the trace against your policy (which tools are allowed, which actions are forbidden,
which secrets must never appear, and how many steps, calls, tokens, seconds and dollars the agent
may use) and report each violation as a finding with its evidence. An optional judge model can review what the
rules cannot see, and its findings are labelled as model-assisted.

## Current status

- 13 attack categories, 47 scenarios, all deterministic and replayable with a seed (categories that need `tool_effects` or `agent_roles` build scenarios only when the policy declares them).
- Authority checks beyond tool allowlists: task-scoped authorization, data-flow tracking across calls, claim-versus-trace comparison, identity and session boundaries, and multi-agent delegation with authority attenuation.
- Terminal, JSON, HTML, Markdown and SARIF reports, with findings tagged to OWASP agentic categories.
- `agentsec replay` to check whether findings still reproduce.
- `agentsec mcp scan` to check MCP server tool, resource and prompt definitions (static, never calls, reads or fetches any of them), and `agentsec test --mcp-listen` to test an agent that uses MCP.
- `agentsec compare` to diff two reports and flag regressions; the packaged GitHub Action can compare a run against a baseline report and post the result as a pull-request comment.
- `attack_packs` / `agentsec test --attack-pack` to add your own scenario categories without forking AgentSec.
- `--format sarif` writes a SARIF 2.1.0 report for GitHub Code Scanning, alongside the JSON, HTML and Markdown formats.
- A Python API and a pytest plugin.
- An opt-in model-assisted judge, never critical and always labelled.
- GitHub Actions annotations and job summary. A packaged, reusable action (`action.yml`) is included.
- Adapters: OpenAI-compatible HTTP (optionally streaming), an in-process `CallableAdapter`, a `LangChainAdapter` for LangChain and LangGraph agents, and an in-process `ToolHost` for frameworks that run their own tool loop (exercised with LangChain, LangGraph, CrewAI, AutoGen, the OpenAI Agents SDK, Google ADK and smolagents).
- Six deliberately vulnerable reference agents, each with a hardened variant, all offline: a rule-based one, a RAG-backed one that owns its documents and runs tools server-side, three modeled on real daily-use AI agent products (coding, customer-support and browser assistants), each paired with a matching domain attack pack, and a planner/researcher/executor multi-agent team.
- 427 automated tests (426 pass and 1 is skipped without the optional LangGraph extra; with it installed, 431 run and pass).
- Benchmarks with checked-in results: the same scenarios across seven agent frameworks, three memory backends (including mem0 and LangGraph's store), and a real Claude Code CLI session over MCP -- see [Testing](testing.md#what-has-been-tested-against-real-agents-and-frameworks).
