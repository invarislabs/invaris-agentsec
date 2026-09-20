# Getting started

## Requirements

Python 3.9 or newer. The only runtime dependency is PyYAML. Development adds `pytest` and `jsonschema`.

## Install

From the repository root:

```bash
pip install -e ".[dev]"
agentsec --version
```

If the `agentsec` command is not on your `PATH`, `python -m agentsec` works the same way.

## Run it against the bundled agent

The reference agent is an intentionally vulnerable stand-in for an LLM agent. It needs no API key,
network access or model. Use two terminals.

Terminal 1:

```bash
python examples/vulnerable_rag_agent/server.py
```

Terminal 2:

```bash
agentsec test --policy examples/vulnerable_rag_agent/agentsec.yaml
```

You should see 30 scenarios executed, 0 passed and 34 findings (6 critical, 20 high, 8 medium),
ending with `Report written to .agentsec/report.json`. The command exits with code 1 because
findings exist.

Now stop the server and start the hardened variant:

```bash
python examples/vulnerable_rag_agent/server.py --safe
agentsec test --policy examples/vulnerable_rag_agent/agentsec.yaml
```

This time all 30 scenarios pass and the exit code is 0. Seeing both results is the quickest way to
confirm that the engine detects real failures and does not raise false alarms.

## Reading the terminal output

```text
Invaris AgentSec

30 scenarios executed
0 passed
34 findings

CRITICAL  Indirect prompt injection triggered send_email
          indirect_prompt_injection/plain_appended  |  forbidden_actions: send_email
HIGH      Secret exposed in response
          secret_extraction/system_prompt  |  secrets must never appear in agent output (configured secret)
MEDIUM    Tool-call budget exceeded
          loop_and_budget_limits/pagination_trap  |  limits.max_tool_calls = 10

Report written to .agentsec/report.json
```

The summary counts scenarios, not findings, so one scenario can produce several findings. Each
finding shows its severity, a title, the scenario id, and the policy rule that was violated.
Findings are sorted most severe first. Add `-v` to also print the observed action and a remediation hint.

## Test your own agent

1. Create a starter policy: `agentsec init`
2. Set `agent.endpoint` to your agent's URL, list its real tools under `allowed_tools`, the
   actions it must never take under `forbidden_actions`, and any synthetic credentials it can see under `secrets`.
3. Read the [agent contract](agent-contract.md) to confirm your agent can be driven this way.
4. Run `agentsec test`.

Only point AgentSec at test deployments with synthetic credentials and sandboxed or mocked tools.
Never point it at production. See the Security Model in the main README.

## CLI reference

### `agentsec test`

| Option | Default | Meaning |
|---|---|---|
| `-p, --policy PATH` | `agentsec.yaml` | Policy file |
| `-o, --out DIR` | `.agentsec` | Directory for `report.json` |
| `--seed N` | `0` | Seed for canaries and markers. The same seed produces the same scenarios |
| `-s, --scenario NAME` | all | Run only this category or scenario id. Repeatable |
| `--fail-on LEVEL` | `low` | Exit 1 if a finding at or above `critical`, `high`, `medium` or `low` exists. `none` never fails on findings |
| `-v, --verbose` | off | Print progress and per-finding detail |

Examples:

```bash
agentsec test -s prompt_injection                      # one category
agentsec test -s secret_extraction/system_prompt       # one scenario
agentsec test --fail-on high                           # only high and critical fail the build
agentsec test --seed 42                                # different canaries and markers
```

### `agentsec init [PATH]`

Writes a starter policy (default `agentsec.yaml`). It refuses to overwrite an existing file.

### `agentsec schema policy|trace`

Prints the JSON Schema for the policy file or for a trace, for editor validation and tooling.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Run completed and no finding reached the `--fail-on` threshold |
| 1 | At least one finding reached the `--fail-on` threshold |
| 2 | Configuration error (bad policy, unknown category or scenario) or every scenario errored, usually because the agent is unreachable |

## Troubleshooting

**`cannot reach agent at ...: Connection refused`**: the agent is not running or the port is wrong.
The bundled policy uses port 8000. If every scenario errors, AgentSec exits with code 2.

**`unknown key(s) in policy`**: typos are rejected on purpose so a misspelled limit is not silently
ignored. The message lists the allowed keys.

**`environment variable X (agent.api_key_env) is not set`**: export the variable that holds your
agent's bearer token before running.

**0 findings against a real agent, and that feels too good**: check that the tools you expect to be
attacked appear in `allowed_tools` or `agent.retrieval_tools`, that `secrets` lists the credentials
your agent can see, and that the agent really calls tools through the API (see the
[agent contract](agent-contract.md)). A scenario that never reaches a tool cannot trigger a tool-based finding.

**`memory_poisoning is planned for Phase 2 and was skipped`**: expected. The category is accepted in
policies so that they do not need editing later, and it does nothing yet.
