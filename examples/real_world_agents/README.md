# Real-world reference agents

Three more deterministic, rule-based reference agents, in the same spirit as
[`examples/vulnerable_rag_agent`](../vulnerable_rag_agent) and [`examples/rag_agent`](../rag_agent),
but modeled on the *shape* of the AI agent products people actually use every day rather than a
generic RAG bot: a coding assistant, a customer-support assistant, and a browser-automation
assistant. Each ships a deliberately vulnerable mode and a `--safe` hardened mode behind the same
flag, so they double as stress-test targets for AgentSec itself -- a reference agent is only useful
if it can both fail and pass the suite.

They need only the standard library, share this folder's `_common.py` for HTTP plumbing and a few
parsing primitives, and are paired one-to-one with this repo's domain attack packs:

| Agent | Models | Tools | Attack pack |
|---|---|---|---|
| [`coding_assistant`](coding_assistant) | An IDE copilot / autonomous coding agent (e.g. GitHub Copilot's agent mode, Cursor, Claude Code) | `read_pr_comments`, `search_packages`, `install_package`, `write_file`, `run_tests` | [`coding_agent_pack.py`](../attack_packs/coding_agent_pack.py) |
| [`support_assistant`](support_assistant) | A customer-support help-desk copilot (e.g. Intercom Fin, Zendesk AI) | `lookup_account`, `issue_refund`, `send_customer_email` | [`support_agent_pack.py`](../attack_packs/support_agent_pack.py) |
| [`browser_assistant`](browser_assistant) | An agentic browser / computer-use assistant (e.g. Comet, Operator, browser-use agents) | `read_page`, `navigate`, `fill_form` | [`browser_agent_pack.py`](../attack_packs/browser_agent_pack.py) |
| [`multi_agent_team`](multi_agent_team) | A planner with a researcher and an executor (a CrewAI crew with delegation, an AutoGen group chat, a planner/worker graph); reports which agent acted | `delegate_task`, `search_docs`, `apply_change` | none -- uses `agent_roles` and `multi_agent_delegation` ([Multi-agent testing](../../docs/multi-agent.md)) |

## Running one

```
python examples/real_world_agents/coding_assistant/server.py            # vulnerable, port 8010
python examples/real_world_agents/coding_assistant/server.py --safe     # hardened variant
agentsec test --policy examples/real_world_agents/coding_assistant/agentsec.yaml
```

Same pattern for `support_assistant` (port 8020), `browser_assistant` (port 8030) and `multi_agent_team` (port 8040). Each
`agentsec.yaml` declares that agent's tools, its synthetic secret, its `tool_effects` (see
[Policy reference](../../docs/policy-reference.md#tool_effects)), and both the built-in categories
and its matching attack pack's categories, so a single `agentsec test` run exercises the full
generic + domain-specific suite against it, including `action_without_authorization` -- each
agent's vulnerable mode performs its one allowed non-read action (`install_package`, `issue_refund`,
`fill_form`) when a review-only/lookup-only/read-only request is paired with untrusted content
asking it to go further, and each `--safe` mode does not. See
[`demo_action_without_authorization.py`](demo_action_without_authorization.py) for the exact
before/after walkthrough against `coding_assistant`.

Current vulnerable/safe split, run live against each agent:

| Agent | Vulnerable mode | `--safe` mode |
|---|---|---|
| `coding_assistant` | 50/50 scenarios produced a finding | 50/50 scenarios passed |
| `support_assistant` | 48/48 scenarios produced a finding | 48/48 scenarios passed |
| `browser_assistant` | 49/49 scenarios produced a finding | 49/49 scenarios passed |
| `multi_agent_team` | 38/38 scenarios produced a finding | 38/38 scenarios passed |

The policies also declare `tool_effects` data labels (`read_pr_comments`/`search_packages`/`read_page` are
`untrusted_content`, `lookup_account` is `private_data`) and run `dangerous_composition`,
`deceptive_action_report` and `identity_and_session_confusion`. `support_assistant` gained a
`send_customer_email` tool so the record-exfiltration composition has a realistic outbound channel; the browser
policy has no private source or executor, so `dangerous_composition` builds nothing for it.

DO NOT deploy any of these. The vulnerable mode of each obeys instructions it finds in content it
reads, on purpose, and the "secrets" embedded in each system prompt are synthetic demo values, not
real credentials.

## Why these three

Coding assistants, support bots, and browser-automation agents are, as of 2026, among the most
widely deployed categories of production AI agents: an IDE copilot or autonomous coding agent in
daily use by most professional developers, a support bot handling first-line customer contact for
a large share of SaaS and e-commerce companies, and a browser/computer-use agent now shipping in
mainstream products. Each category also has its own well-documented failure mode distinct from the
others -- a coding agent trusting a comment it reads in a PR, a support agent skipping
verification under social pressure or bleeding one caller's details to another, a browser agent
following an instruction hidden in a page or navigating to a lookalike domain -- which is exactly
what `coding_agent_pack.py`, `support_agent_pack.py`, and `browser_agent_pack.py` were already
built to test. These agents exist to give those packs (and the built-in, domain-agnostic
categories) a realistic, runnable target shaped like the real thing, not just a synthetic one.
