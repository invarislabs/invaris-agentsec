# Dashboard

`agentsec dashboard` opens a local, read-only web view of the reports AgentSec already writes. It is
for working through findings: which attack categories the agent fails, what it did, the trace that
proves it, and the command to reproduce it.

```bash
agentsec test --policy agentsec.yaml        # writes .agentsec/report.json
agentsec dashboard                          # http://127.0.0.1:8710/
```

The dashboard never runs scenarios and never contacts your agent. It reads `report.json` (from
`agentsec test` and `agentsec replay`) and `mcp-report.json` (from `agentsec mcp scan`), so it works the
same on a run you just made, a report downloaded from a CI artifact, or a teammate's file. It has no
dependencies beyond AgentSec itself and loads nothing from the internet.

## Options

| Option | Meaning |
|---|---|
| `PATH ...` | Report files or directories to search (default: the current directory). Directories are searched recursively, six levels deep, for files named `report.json` and `mcp-report.json`, skipping `.git`, `node_modules`, virtualenvs, `build`, `dist` and similar. A file passed explicitly can have any name, for example `baseline-from-ci.json` |
| `--host` | Address to listen on. Default `127.0.0.1`, this machine only |
| `--port` | Port, default `8710`. `0` picks a free one |
| `--open` | Open the dashboard in your browser |
| `--verbose`, `-v` | Log each request |

New and rewritten reports appear while the page is open. When the report you are looking at is
overwritten by a newer `agentsec test`, the page offers to show the new run.

## What it shows

**Reports.** Every report found, grouped by agent (or MCP server), newest first, with its severity mix.

**Overview** of an agent test:

- A plain verdict ("43 findings in 35 of 35 scenarios", "No scenario could run") and the counts behind it:
  scenarios, passed, with findings, errors, not observable.
- **Scenarios by attack category.** One square per scenario, coloured by its worst finding, or marked passed,
  errored or not observable. Select a square to open that scenario's trace.
- **OWASP agentic categories.** Findings per ASI01-ASI10, all ten listed so gaps are visible. The mapping is
  Invaris' closest-fit judgement, as in every other report format.
- **How the attack arrived.** Scenarios with findings by vector: the user's message, a retrieved document, or
  tool output.
- **Rules that fired** and **tools the agent called**, with each tool classified against the policy
  (forbidden action, not in `allowed_tools`, allowed).
- **Run.** Steps, tool calls, tokens, cost (shown as unknown rather than zero when the agent reports none and
  no `agent.pricing` is set), outcomes, limits that stopped scenarios, multi-session scenarios and the agents
  seen in a multi-agent run. Errors such as an unreachable agent are listed at the top.

**Findings.** Filter by severity, category, rule, OWASP category and source (deterministic or
model-assisted), or search. Each finding shows what the agent did, the policy it violated, the input, the
evidence events rendered as a trace, the remediation, and copyable commands:

```bash
agentsec replay .agentsec/report.json --policy agentsec.yaml --finding '<finding id>'
agentsec test --policy agentsec.yaml --seed 0 -s <scenario id>
```

**Scenarios.** The full trace of each scenario as a timeline: user messages, agent replies, tool calls with
their arguments, simulated tool results, limits and errors. Events cited as evidence are highlighted and
linked to their findings. Memory scenarios are split into their first and follow-up conversations
(`meta.phase`); multi-agent traces show which agent acted and who delegated to it (`meta.actor`,
`meta.delegated_by`); over-budget calls and calls the agent executed itself are labelled.

**Policy.** The policy as it was run, from the report: agent settings, allowed tools with their declared
`tool_effects`, forbidden actions, limits, spend limits, address allowlist, agent roles, categories, attack
packs, the judge, the number of configured secrets (never their values) and the policy file's hash.

**MCP scans.** The server's tools, resources and prompts with the descriptions exactly as the server sent
them, and the findings against each.

**Compare runs.** Pick a baseline and a current report. The comparison is `agentsec compare`'s own logic:
findings are matched by id and listed as new, severity increased, fixed, severity decreased, unchanged, or not
comparable (the scenario is missing or errored in the current run, so it cannot count as fixed), with the same
warnings about differing seeds, policies and scenario sets.

`agentsec test` overwrites `report.json` in its output directory on every run, so keep a run you want to
compare against in its own directory:

```bash
agentsec test --out .agentsec/baseline
# ... change the agent ...
agentsec test --out .agentsec/current
agentsec dashboard .agentsec
```

## Security

Reports contain your agent's real responses and the adversarial payloads AgentSec sent it, so the dashboard
treats them as hostile input and itself as sensitive:

- It listens on `127.0.0.1` by default and warns when told to listen anywhere else. There is no login, so only
  listen on another address on a network you trust.
- It answers `GET` and `HEAD` only, serves nothing but its own files and the reports it found (by an opaque id,
  never by a path from the request), and rejects requests whose `Host` header is not the address it listens on,
  so a web page you visit cannot read your reports through DNS rebinding.
- Report text is always inserted into the page as text, never parsed as HTML, and a strict Content Security
  Policy allows only the dashboard's own script, styles and fonts.
- Invisible and control characters (zero-width spaces, bidirectional overrides, tag characters) are shown as
  visible `U+XXXX` marks wherever report text appears, and non-ASCII characters in tool names are marked, so
  hidden instructions and look-alike tool names are visible rather than silently rendered.
- Secrets are already masked in the report files; the dashboard shows them exactly as masked there.

## Hosted dashboard

A hosted dashboard for teams and run history is in development. Its code is open source under Apache-2.0 at
[`invarislabs/invaris-agentsec-dashboard`](https://github.com/invarislabs/invaris-agentsec-dashboard), so you can
run it yourself. The hosted service will be free at launch; a few premium features added later will be paid and
private. The local `agentsec dashboard` stays free and open source.

Reports reach the hosted dashboard only when you send them:

```bash
export AGENTSEC_TOKEN=...        # a project token from the hosted dashboard
agentsec upload .agentsec/report.json --server https://<your dashboard>
```

| Option | Meaning |
|---|---|
| `REPORT` | `report.json` or `mcp-report.json` (default `.agentsec/report.json`) |
| `--server` | The dashboard URL, or set `AGENTSEC_SERVER`. HTTPS is required, except for `localhost` |
| `--token-env` | Environment variable that holds the token (default `AGENTSEC_TOKEN`). The token is never accepted as an argument |
| `--branch`, `--commit`, `--ci-url` | Recorded with the run; read automatically inside GitHub Actions |
| `--label` | A short label for the run, for example the model or prompt version |
| `--no-traces` | Leave out full scenario transcripts; findings, their evidence and run statistics are still sent |

Secrets are already masked in the report file, but traces contain your agent's real responses; use
`--no-traces` if they should not leave your machine or CI. In GitHub Actions, set the action's `dashboard-url`
and `dashboard-token` inputs; see [GitHub Actions](github-actions.md#inputs).

## Limits

- It shows what the report files contain. Anything a report does not record (for example the full scenario
  description, or a tool call a framework rejected before it reached AgentSec) is not shown.
- History is whatever report files are on disk. There is no database and no hosted service.
- One process serves one user. It is not a team server.
