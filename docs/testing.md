# Testing

This page covers the automated tests for AgentSec itself, ways to verify the engine by hand, and how to run AgentSec in CI.

## Run the automated tests

```bash
pip install -e ".[dev]"
pytest
```

All 133 tests should pass in a few seconds. They need no network access or API keys. The end-to-end tests start the reference agent
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
| `tests/test_api_and_plugin.py` | The Python API against the reference agents, and the pytest plugin run in a subprocess |

The two most important checks are the pair in `test_end_to_end.py`: the vulnerable agent must trigger findings in all 8 categories,
and the safe agent must pass all 34 scenarios. Together they protect against both missed detections and false alarms.

## Verify by hand

1. Start the vulnerable agent and run the suite, as in [Getting started](getting-started.md#run-it-against-the-bundled-agent).
   Expect 34 executed, 0 passed, 42 findings (10 critical, 24 high, 8 medium), exit code 1.
2. Restart with `--safe`. Expect 34 passed, 0 findings, exit code 0.
3. Stop the server and run again. Expect every scenario to be reported as an error and exit code 2, not a pass.
4. Run `agentsec test -s prompt_injection --seed 1` twice and compare the reports. Scenarios and finding ids should match.
   Change the seed and the markers change.
5. Check masking: `grep -c "sk-live-INVARIS-DEMO-7f3a9c1e5b2d" .agentsec/report.json .agentsec/report.html` should print `0` for both.
6. Open `.agentsec/report.html` and check that findings expand and show their evidence.
7. Replay: run the vulnerable agent, then `agentsec replay .agentsec/report.json -p examples/vulnerable_rag_agent/agentsec.yaml`. Every line should be REPRODUCED.
   Restart with `--safe` and replay again: every line should be NOT REPRODUCED and the exit code 0.

Findings are deterministic against the reference agent, so these numbers are stable across runs and machines.

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
- Update the scenario count assertions (`34`) in `test_end_to_end.py` and `test_api_and_plugin.py` if you add scenarios.
- Custom adapters in tests must accept the `session` keyword: `def chat(self, messages, tools, session=None)`.
