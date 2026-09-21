# Invaris AgentSec documentation

These docs describe what is built today: the Phase 1 local testing engine and most of Phase 2. Planned work is in the
[roadmap](../README.md#roadmap) and is not described here.

| Document | Read it to... |
|---|---|
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
| [Extending](extending.md) | Add a scenario category, an evaluator or an adapter |

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

- 8 attack categories, 34 scenarios, all deterministic and replayable with a seed.
- Terminal, JSON, HTML and Markdown reports, with findings tagged to OWASP agentic categories.
- `agentsec replay` to check whether findings still reproduce.
- A Python API and a pytest plugin.
- An opt-in model-assisted judge, never critical and always labelled.
- GitHub Actions annotations and job summary. A packaged, reusable action is planned.
- One adapter: OpenAI-compatible HTTP.
- Two deliberately vulnerable reference agents, each with a hardened variant, all offline: a rule-based one, and a RAG-backed one that owns its documents and runs tools server-side.
- 80 automated tests.
