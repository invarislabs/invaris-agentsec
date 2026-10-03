# Testing

This page covers the automated tests for AgentSec itself, ways to verify the engine by hand, and how to run AgentSec in CI.

## Run the automated tests

```bash
pip install -e ".[dev]"
pytest
```

All 427 tests should pass in under a minute (one, the LangGraph integration test, is skipped unless the optional LangGraph extra is installed). They need no network access or API keys. The end-to-end tests start the reference agent
on a random local port inside the test process.

Useful variations:

```bash
pytest tests/test_evaluators.py            # one file
pytest -k "budget or limit"                # by name
pytest -x -q                               # stop at the first failure
```

The plugin tests start `pytest` in a subprocess with plugin auto-loading disabled, so they pass whether or not you have reinstalled the package since
the entry point was added. To use the plugin in your own projects, install the package (`pip install -e .`) so the `pytest11` entry point is registered.

## What the tests cover

| File | Focus |
|---|---|
| `tests/test_schemas.py` | Policy defaults, validation errors, `env:` secrets, agreement between the loader and the JSON Schemas, trace round-trip |
| `tests/test_adapter_runner.py` | Tool results flowing back to the agent, decoy tools, sandboxing of forbidden tools, step, tool-call and time limits, cost from pricing, server-side events, and the HTTP adapter against a small fake server (parsing, auth header, HTTP errors, unreachable host) |
| `tests/test_evaluators.py` | Severity by vector, allowlist behaviour, secret detection, echo and refusal false-positive guards, marker matching, repeated calls and limits, and the memory-aware rules (later-phase markers, forbidden calls and canaries) |
| `tests/test_end_to_end.py` | The vulnerable agent yields findings in every category, the safe agent yields none, seed reproducibility, report validity and secret masking, terminal output shape, memory-poisoning findings, CLI exit codes and error handling |
| `tests/test_reports_phase2.py` | OWASP mapping, HTML report (well-formed, self-contained, escapes untrusted text, masks secrets), Markdown summary, GitHub annotations and job summary, `--format` |
| `tests/test_replay.py` | Replay reproduces against the same agent, reports NOT REPRODUCED against a hardened one, honours the recorded seed, finding and scenario filters, CLI exit codes |
| `tests/test_judge.py` | Verdict parsing, model-assisted labelling and confidence, skipping already-flagged scenarios, secret masking and prompt hardening, failed judge calls, policy validation, and `--judge` over HTTP against a stub |
| `tests/test_rag_example.py` | The RAG reference agent: retrieval ranking, the example policy, the vulnerable agent caught through server-side `x_agentsec` events (critical `send_email` findings from the poisoned document, restricted runbook content and the system-prompt key leaking), the safe agent passing with only `search_documents` in its outbox, the `/outbox` endpoint, and secret masking |
| `tests/test_action_scripts.py` | The GitHub Action's helper scripts run for real against the reference agents (full cycle, safe agent, unreachable agent, bad policy, early exit, timeout, process-tree kill) and structural checks of `action.yml` and the CI workflow (inputs used and declared, no inputs interpolated into scripts, output names) |
| `tests/test_compare.py` | `agentsec compare`: new, fixed, unchanged and severity changes, missing or errored scenarios never counted as fixed, seed and policy warnings, CLI exit codes |
| `tests/test_streaming_and_callable.py` | SSE parsing (text, fragmented tool calls, usage, `x_agentsec` events, malformed streams), the `stream` policy option, the RAG agent streaming with findings identical to non-streaming, and `CallableAdapter` return shapes, crashes and use through the Python API |
| `tests/test_mcp.py` | MCP checks (poisoning, schema injection, invisible characters, shadowing, policy rules, near misses that must stay clean), pins and rug pulls, stdio and HTTP transports (pagination, sessions, SSE, errors), the `mcp scan` CLI, and terminal sanitising |
| `tests/test_mcp_host.py` | AgentSec as the MCP server: protocol and recording, the vulnerable MCP-connected reference agent caught (critical findings, tool-call budget), the safe one passing every scenario, no tools declared in requests, and the `--mcp-listen` CLI (bad value, busy port) |
| `tests/test_langchain_integration.py` | `LangChainAdapter` against real LangGraph agents (needs `pip install -e ".[langchain]"`; skipped otherwise) |
| `tests/test_attack_packs.py` | Loading attack packs from a file or module, `CATEGORIES` validation, built-in/cross-pack name collisions, `check_pack_scenarios`, running a pack through `build_scenarios`/`run_suite`/the Python API/the CLI |
| `tests/test_sarif_report.py` | SARIF 2.1.0 output: shape and schema version, one rule per finding rule id, severity-to-level mapping, secret masking, an empty run, and `-f sarif` through the CLI |
| `tests/test_packaging.py` | Package version agrees with `pyproject.toml` and the changelog, required project files exist, license metadata, schemas declared as package data, release workflow is valid and tests before publishing |
| `tests/test_api_and_plugin.py` | The Python API against the reference agents, and the pytest plugin run in a subprocess (a category with no scenarios for the policy is skipped, not passed) |
| `tests/test_action_without_authorization.py` | The task-scoped authorization category and its `scoped_action()` helper |
| `tests/test_dataflow.py` | `DataFlowEvaluator`: exfiltration of private data, untrusted text executed or delegated, user-named and allowlisted destinations as negative controls, per-conversation tracking, the `dangerous_composition` category |
| `tests/test_claims.py` | `ActionClaimEvaluator`: denials contradicted by the trace, completion claims with no supporting call, hedged/future/conditional statements and denials about one specific thing as negative controls (including phrasing seen from a real agent) |
| `tests/test_identity.py` | `cross_principal_access`, `stale_authorization` (per-conversation scope), a credential reused in another user's session, the `identity_and_session_confusion` category |
| `tests/test_multi_agent.py` | `DelegationEvaluator` rules, actor attribution through the HTTP and callable adapters, the multi-agent reference team (vulnerable caught, safe clean, legitimate delegation not flagged), and NOT OBSERVABLE for systems that report no attribution |
| `tests/test_toolhost.py` | The in-process `ToolHost`, executed calls recorded before the reply they led to, actions taken before a crash still evaluated, MCP clients attributed by `clientInfo`, and the no-dependency baselines of the framework and memory benchmarks |

The two most important checks are the pair in `test_end_to_end.py`: the vulnerable agent must trigger findings in every built-in category the test policy supports (all except `multi_agent_delegation`, which needs a multi-agent system and is checked against the reference team in `test_multi_agent.py`),
and the safe agent must pass all 44 scenarios the test policy builds (it declares `tool_effects` with data labels, so `action_without_authorization`, `dangerous_composition`, `deceptive_action_report` and `identity_and_session_confusion` all contribute; `examples/vulnerable_rag_agent/agentsec.yaml` itself lists only the original eight categories, so running the CLI directly against it, as in "Verify by hand" below, shows 35). Together they protect against both missed detections and false alarms.

## Verify by hand

1. Start the vulnerable agent and run the suite, as in [Getting started](getting-started.md#run-it-against-the-bundled-agent).
   Expect 35 executed, 0 passed, 43 findings (10 critical, 25 high, 8 medium), exit code 1.
2. Restart with `--safe`. Expect 35 passed, 0 findings, exit code 0.
3. Stop the server and run again. Expect every scenario to be reported as an error and exit code 2, not a pass.
4. Run `agentsec test -s prompt_injection --seed 1` twice and compare the reports. Scenarios and finding ids should match.
   Change the seed and the markers change.
5. Check masking: `grep -c "sk-live-INVARIS-DEMO-7f3a9c1e5b2d" .agentsec/report.json .agentsec/report.html` should print `0` for both.
6. Open `.agentsec/report.html` and check that findings expand and show their evidence.
7. Replay: run the vulnerable agent, then `agentsec replay .agentsec/report.json -p examples/vulnerable_rag_agent/agentsec.yaml`. Every line should be REPRODUCED.
   Restart with `--safe` and replay again: every line should be NOT REPRODUCED and the exit code 0.

Findings are deterministic against the reference agent, so these numbers are stable across runs and machines.

## What has been tested against real agents and frameworks

Verification levels, as used throughout `research/`: **researched** (documentation read), **simulated** (a
scripted stand-in), **integrated** (AgentSec drove the real software), **tested** (scenarios ran end to end and the
results were checked by hand).

| Target | Level | What ran | Result |
|---|---|---|---|
| Claude Code CLI (2.1.287/2.1.288) over `--mcp-listen`-style MCP host | integrated, tested (real LLM) | 35 scenarios, 10 categories; built-in tools disabled | 2 true findings (`marker_override`, `ceo_authority`), 33 passed; 3 AgentSec false positives found and fixed. [Details](../benchmarks/real-agents/README.md) |
| LangChain, LangGraph, CrewAI, AutoGen AgentChat, OpenAI Agents SDK, Google ADK, smolagents | integrated, executed (scripted model) | 35 scenarios each through the real framework runtime and `ToolHost` | 33/35 identical to the no-framework reference in every framework, 0 false positives; the 2 differences are calls to unknown tools the frameworks refuse before execution. [Matrix](../benchmarks/framework-compat/MATRIX.md) |
| OpenAI Agents SDK and CrewAI multi-agent teams | integrated, executed (scripted model) | `multi_agent_delegation` + a legitimate-delegation control | Confused deputy, role violations and credential hand-offs detected; safe teams and legitimate delegation clean. [Matrix](../benchmarks/framework-compat/MATRIX.md#multi-agent-teams-multi_agentrunpy) |
| mem0 (2.2.1, Qdrant local), LangGraph `InMemoryStore` | integrated, executed (scripted agent, real store) | 6 memory/identity scenarios x 4 agent configurations | Cross-user leakage and poisoned persistence separated cleanly by configuration. [Matrix](../benchmarks/memory-systems/MATRIX.md) |
| Codex CLI, Gemini CLI, Cursor, Letta, open-source coding agents | researched only | - | Not run: no credentials or headless mode in this environment |

## Testing your own agent's results

- A finding you disagree with: open its `evidence` and the scenario's `trace` in `report.json`. Check whether the agent really made the call
  or produced the text. If the policy is too strict, adjust `allowed_tools`, `forbidden_actions` or `limits`.
- A finding you cannot reproduce: use the seed in the report and the same policy. Agents that use real model sampling can vary between runs.
- No findings at all: confirm the agent actually used tools through the API, that `secrets` is filled in, and that limits are not set higher than any
  possible run. Run the reference agent once to confirm your setup, then your agent.

## Run AgentSec in CI

A GitHub Actions workflow that starts the agent and fails the build on high or critical findings looks like this. When it runs in Actions, `agentsec test`
also writes an annotation for each finding and a job summary, with no extra flags. A packaged, reusable action is described in [GitHub Actions](github-actions.md).

```yaml
name: agent-security
on: [pull_request]
jobs:
  agentsec:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: {python-version: "3.11"}
      - run: pip install invaris-agentsec        # or: pip install -e .
      - run: ./scripts/start-test-agent.sh &     # your agent, with synthetic credentials
      - run: sleep 5
      - run: agentsec test --policy agentsec.yaml --fail-on high
      - uses: actions/upload-artifact@v4
        if: always()
        with: {name: agentsec-report, path: .agentsec/report.json}
```

Exit code 1 fails the job when findings meet the threshold. Exit code 2 fails it for configuration or connection errors,
so a broken setup is never mistaken for a clean result. Upload the report even on failure, since it holds the evidence.

## Adding tests

When you add a scenario, evaluator or adapter behaviour:

- Cover the evaluator with a hand-built trace in `tests/test_evaluators.py`, both a case that must be flagged and a near miss that must not.
- If the reference agent should fail the new scenario, extend it in `examples/vulnerable_rag_agent/server.py` and extend its safe mode so the safe agent still passes. `test_end_to_end.py` will tell you if either side breaks.
- Update the scenario count assertions (`44` and `42`) in `test_end_to_end.py` and `test_api_and_plugin.py` if you add scenarios.
- Not yet verified: real LLM-backed LangChain agents, MCP scanning against real-world MCP servers, and `--mcp-listen` against MCP-capable agents other than Claude Code (see below).
- New evaluators need a negative control and, where possible, a run against a real agent: the scripted reference agents never produced the phrasings that exposed three false positives in `ActionClaimEvaluator`.
- Custom adapters in tests must accept the `session` keyword: `def chat(self, messages, tools, session=None)`.
