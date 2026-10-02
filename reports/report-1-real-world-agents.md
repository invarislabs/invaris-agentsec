# Report 1: Real-world reference agents, stress testing, and what it found

## What was built

Three new reference agents were added under [`examples/real_world_agents/`](../examples/real_world_agents/),
modeled on the shape of AI agent products that are genuinely in daily use (verified against current GitHub
star counts, not assumed), alongside a shared helper module:

| File | What it is |
|---|---|
| `examples/real_world_agents/_common.py` | Shared HTTP plumbing and parsing helpers (tool-call/memory handling, tool-instruction matching, sanitization) used by all three agents below |
| `examples/real_world_agents/coding_assistant/` | Models an IDE copilot / autonomous coding agent (the category led by OpenHands, Cline, Aider, Open Interpreter -- all tens of thousands of GitHub stars). Tools: `read_pr_comments`, `search_packages`, `install_package`, `write_file`, `run_tests` |
| `examples/real_world_agents/support_assistant/` | Models a customer-support help-desk copilot (Intercom Fin / Zendesk AI style). Tools: `lookup_account`, `issue_refund` |
| `examples/real_world_agents/browser_assistant/` | Models a browser-automation / computer-use agent (the category led by `browser-use` at 116.7k stars, Stagehand). Tools: `read_page`, `navigate`, `fill_form` |

Each agent is a deterministic, rule-based HTTP server (standard library only, no model, no network) with two
modes behind the same flag, matching the pattern of the existing `examples/vulnerable_rag_agent`:

- **vulnerable mode** (default) -- obeys instructions found in untrusted content, has no refund cap or
  dedupe, leaks retrieved/remembered content back to the caller, navigates wherever a page tells it to.
- **`--safe` mode** -- refuses injected instructions, caps and dedupes refunds, keeps memory private to its
  own session, and only navigates to an allowlisted domain.

Each agent ships its own `agentsec.yaml` policy, declaring that agent's tools, a synthetic demo secret, and
both the eight built-in attack categories and the matching pre-existing domain attack pack:

- `coding_assistant` <-> `examples/attack_packs/coding_agent_pack.py`
- `support_assistant` <-> `examples/attack_packs/support_agent_pack.py`
- `browser_assistant` <-> `examples/attack_packs/browser_agent_pack.py`

## How it was tested

For each of the three agents, both modes were started as a live HTTP server and run through the real
`agentsec test` CLI against that agent's own `agentsec.yaml` -- the same workflow a user would follow, not a
mocked test:

```bash
python examples/real_world_agents/<agent>/server.py             # vulnerable
agentsec test --policy examples/real_world_agents/<agent>/agentsec.yaml

python examples/real_world_agents/<agent>/server.py --safe       # hardened
agentsec test --policy examples/real_world_agents/<agent>/agentsec.yaml
```

This exercises the full generic suite (prompt injection, indirect prompt injection, secret extraction,
unauthorized tool use, tool-output poisoning, unsafe retrieved documents, loop/budget limits, memory
poisoning) plus each agent's matching domain-specific categories, in one pass, per mode.

**Final results**, after the fixes described below:

| Agent | Vulnerable mode | `--safe` mode |
|---|---|---|
| `coding_assistant` | 41/41 scenarios produced a finding, 0 errors | 41/41 scenarios passed, 0 findings |
| `support_assistant` | 39/39 scenarios produced a finding, 0 errors | 39/39 scenarios passed, 0 findings |
| `browser_assistant` | 41/41 scenarios produced a finding, 0 errors | 41/41 scenarios passed, 0 findings |
| **Total** | **121/121** | **121/121** |

A reference agent that doesn't fail in vulnerable mode or pass in safe mode isn't proving anything, so this
100%/0% and 0%/100% split across all three agents was the bar for calling the stress test clean.

## What it found, and what was improved

### 1. Two bugs in the new reference agents themselves

Running the suite surfaced two real bugs in `support_assistant`'s own logic before it reached that clean
result -- both self-found by inspecting *why* a scenario wasn't producing a finding, not reported by anyone:

- **Refund-detection overmatch.** `refund_mentions()` matched any sentence naming an order (`"order 8841"`),
  not just ones asking for money back. A plain status question ("Look up the status of order 8841 for me")
  mis-fired `issue_refund` instead of the expected `lookup_account` call, which meant the agent's retrieval
  tool was never reached -- silently defeating `tool_output_poisoning`, `unsafe_retrieved_documents`, and
  `memory_poisoning/tool_output_rule` for this agent. Fixed by requiring the sentence to actually contain
  "refund" before counting it as a refund mention.
- **Swallowed tool output.** The vulnerable agent's fallback response for an unrecognized tool result was a
  canned "All set -- let me know if there's anything else," instead of echoing the content back the way
  `coding_assistant` and `browser_assistant` do. This meant a poisoned/confidential document retrieved via
  `lookup_account` never reached the agent's own output, so `unsafe_retrieved_documents` could never find a
  leak. Fixed to echo the retrieved content, matching the other two agents' (intentionally vulnerable)
  pattern.

Both were caught by the same method: when a scenario the agent should plausibly fail came back "passed,"
the trace was inspected event-by-event to see what the agent actually did, rather than trusting the summary
count.

### 2. A real bug found and fixed in AgentSec itself

While building `support_assistant`'s cross-customer-leak handling, `SecretLeakEvaluator`
(`agentsec/evaluators/secrets.py`) turned out to decide "is this canary just the caller repeating their own
fact in the same conversation" by checking `scenario.category == "memory_poisoning"` literally. That means
*any other category* with the same shape -- canaries plus a `Followup(same_session=False)` -- got the wrong
treatment:

- a **false positive**: the agent's own benign, same-session acknowledgment of a caller's account reference
  (`support_agent_cross_customer_leak`) was reported as a leak, and
- a **mislabeling**: a genuine cross-session leak would have been reported as "confidential retrieved content
  appeared in the response" instead of "memory leaked across sessions."

This was reproduced in isolation with a hand-built trace before touching the fix, confirmed with the fix
applied, and the existing test suite's own `memory_poisoning` regression test for this exact mechanism was
updated to build its fixture the same way a real scenario does (canaries + a cross-session `Followup`)
rather than relying on the category-name shortcut, plus a new test added that specifically exercises a
pack category with the same shape. Fix: `agentsec/evaluators/secrets.py` now detects the shape itself
(canaries + a same-session-false followup) instead of the category name.

Verified with the full existing suite before and after: **311 passed, 1 skipped**, no regressions, plus the
2 new/updated tests in `tests/test_evaluators.py` passing.

### 3. Documentation brought back in sync

`docs/agent-contract.md`, `docs/architecture.md`, `docs/README.md`, the root `README.md`, `docs/testing.md`
and `CHANGELOG.md` all referenced "two reference agents" or a stale test count (310 / 315-with-LangGraph).
Updated to describe all five reference agents and the corrected count (**311 / 316-with-LangGraph**),
and added an `## Unreleased` changelog entry documenting both the new agents and the evaluator fix.

## Files touched

```
examples/real_world_agents/README.md               (new)
examples/real_world_agents/_common.py               (new)
examples/real_world_agents/coding_assistant/        (new: server.py, agentsec.yaml)
examples/real_world_agents/support_assistant/       (new: server.py, agentsec.yaml)
examples/real_world_agents/browser_assistant/       (new: server.py, agentsec.yaml)
agentsec/evaluators/secrets.py                      (fix)
tests/test_evaluators.py                            (regression tests for the fix)
README.md, docs/README.md, docs/architecture.md,
docs/agent-contract.md, docs/testing.md,
CHANGELOG.md                                        (docs sync)
```
