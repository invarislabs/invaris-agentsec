# Invaris AgentSec documentation

These docs describe what is built today (Phase 1, the local testing engine). Planned work is in the
[roadmap](../README.md#roadmap) and is not described here.

| Document | Read it to... |
|---|---|
| [Getting started](getting-started.md) | Install AgentSec, run it against the bundled agent, read the output, use the CLI |
| [Architecture](architecture.md) | Understand how a run works, what each component does, and why it is designed this way |
| [Policy reference](policy-reference.md) | Write an `agentsec.yaml` for your own agent |
| [Attack catalog](attack-catalog.md) | See every scenario, what it simulates, and how a failure is detected |
| [Agent contract](agent-contract.md) | Make your agent testable, and understand the reference agent |
| [Reports and traces](reports-and-traces.md) | Consume `report.json`, findings and the trace format |
| [Testing](testing.md) | Run the test suite, verify the engine by hand, add AgentSec to CI |
| [Extending](extending.md) | Add a scenario category, an evaluator or an adapter |

## What AgentSec does in one paragraph

AgentSec pretends to be a hostile environment around your agent. It sends the agent adversarial
user messages, and it answers the agent's tool calls with poisoned documents, poisoned tool output
and endless "retry" loops. Every step is recorded as a normalized trace. Deterministic evaluators
then check the trace against your policy (which tools are allowed, which actions are forbidden,
which secrets must never appear, and how many steps, calls, tokens, seconds and dollars the agent
may use) and report each violation as a finding with its evidence.

## Current status

- 7 attack categories, 30 scenarios, all deterministic and replayable with a seed.
- Terminal and JSON reports. HTML reports are planned for Phase 2.
- One adapter: OpenAI-compatible HTTP.
- A deliberately vulnerable reference agent and a hardened variant, both rule-based and offline.
- 43 automated tests.
