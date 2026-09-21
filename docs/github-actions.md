# GitHub Actions

AgentSec ships a composite GitHub Action (`action.yml` at the repo root) that installs AgentSec,
optionally starts your agent, runs the suite, uploads the reports and fails the job if findings meet
your threshold.

## Usage

```yaml
name: agent-security
on: [pull_request]
permissions:
  contents: read
jobs:
  agentsec:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: invaris-labs/agentsec@main   # adjust to where you host this repo
        with:
          policy: agentsec.yaml
          fail-on: high
          start-command: python my_agent/server.py --port 8000
          wait-for-url: http://127.0.0.1:8000/
```

If your agent is already running (a staging URL in the policy), omit `start-command`.

## Inputs

| Input | Default | Meaning |
|---|---|---|
| `policy` | `agentsec.yaml` | Policy file |
| `fail-on` | `low` | Severity threshold (`low`, `medium`, `high`, `critical`, `none`) |
| `seed` | `0` | Scenario seed |
| `formats` | `json,html,markdown` | Report formats |
| `judge` | empty | Set to enable the model-assisted judge |
| `start-command` | empty | Command that starts the agent in the background |
| `wait-for-url` | empty | URL polled until the agent answers (any HTTP response counts) |
| `wait-timeout` | `60` | Seconds to wait for the agent |
| `working-directory` | `.` | Where to run |
| `out` | `.agentsec` | Report directory |
| `python-version` | `3.11` | Python to set up (empty to skip) |
| `package` | action checkout | What to `pip install` |
| `extra-args` | empty | Extra `agentsec test` arguments, e.g. `-s prompt_injection/ignore_previous` |
| `upload-artifact` | `true` | Upload the report directory |
| `artifact-name` | `agentsec-reports` | Artifact name |

## Outputs

`exit-code` (0 clean, 1 findings at or above threshold, 2 config/connection error), `findings`,
`scenarios`, `report-dir`.

## How it works

Logic lives in three scripts under `action/` (`start-agent.sh`, `run-agentsec.sh`, `stop-agent.sh`)
so it can be tested locally. Inputs reach scripts through `env:` and are never interpolated into
`run:` text, which prevents script injection through input values. The run step never fails by
itself: reports are uploaded first, and a final gate step fails the job with the recorded exit code.
The agent is always stopped (`if: always()`).

## Verification status

The three scripts are exercised by `tests/test_action_scripts.py` against the real reference agents,
and the YAML wiring is checked structurally. The workflow itself (including `.github/workflows/ci.yml`
and composite outputs after a `continue-on-error` step) has **not** been run on real GitHub Actions
yet. Check the first run.
