# Changelog

All notable changes are listed here. The project follows [Semantic Versioning](https://semver.org/); while the
version is below 1.0, minor releases may change behaviour, and the changes are listed below.

## 0.5.1

- Fix: a real bug in the pull-request comparison comment (`pr-comment`) meant it never posted the
  actual comparison summary -- `action/pr-comment.sh` used `gh api -f body=@file`, and `-f` sends
  the literal string `"@file"` rather than reading the file; it needed `-F`, which does. Every
  comment this feature ever posted showed a placeholder path instead of real content. Fixed, and
  covered by a test that pins the `-F` flag so this can't silently regress.
- Fix: SARIF findings and the JSON report's `replay` hint showed a hardcoded `agentsec.yaml`
  placeholder instead of the real policy file path used for the run. `build_report`,
  `write_reports`, and the CLI now thread the real `--policy` path through.
- New: `.github/workflows/verify-pr-comment.yml`, an opt-in (label-gated) workflow that verifies
  the pull-request comment path against a real `pull_request` event and a real `GITHUB_TOKEN`,
  rather than the fake `gh` binary the unit tests substitute.
- Docs: the findings published by `.github/workflows/self-scan.yml` to this repo's own Code
  Scanning tab are now explicitly flagged, in the docs and in the workflow's job summary, as demo
  findings from the bundled vulnerable reference agent -- not real vulnerabilities in AgentSec.
- `NOTICE` file clarifying that "Invaris" and "AgentSec" are trademarks not covered by the
  Apache-2.0 license, and a Contributor License Agreement (`CLA.md`) with a CLA-bot check for
  external pull requests.

## 0.5.0

- Attack packs: load extra scenario categories from a local file or an installed package (`attack_packs:` in the policy, `agentsec test --attack-pack`, `SecuritySuite(attack_packs=...)`). See docs/extending.md#write-an-attack-pack and examples/attack_packs.
- The GitHub Action can compare a run against an earlier baseline report (`baseline-report`, `compare-fail-on`) and post or update a pull-request comment with the regressions (`pr-comment`). `agentsec.compare` gained `render_markdown`.
- SARIF 2.1.0 report format (`--format sarif`, writes `results.sarif`) for GitHub Code Scanning; the GitHub Action's `formats` input accepts it and docs/github-actions.md shows an `upload-sarif` step.
- `policy.schema.json` now declares `attack_packs`, matching the loader (it was previously accepted by the loader but rejected by the schema).

## 0.4.0

- `agentsec test --mcp-listen HOST:PORT`: AgentSec runs as the MCP server your agent connects to, serves the policy's tools and delivers the scenarios' adversarial content through MCP tool results. Calls the agent makes are recorded and evaluated like any other. Includes an MCP-connected reference agent (`examples/mcp_agent`).
- `LangChainAdapter` for LangChain and LangGraph agents (`agentsec.integrations`), tested against real LangGraph agents.
- The tool-call budget is now also checked for agents that run their own tool loop (through MCP or reported events).

## 0.3.0

- Packaged, reusable GitHub Action (`action.yml`) that starts your agent, runs the suite, uploads reports and gates the job.
- `agentsec compare` to diff two reports and flag regressions.
- Streaming (server-sent events) support with `agent.stream: true`, and `CallableAdapter` for in-process agents.
- `agentsec mcp scan` to check MCP server tool definitions (poisoning, invisible characters, shadowing, policy violations, rug pulls via `--pin` and `--recheck`). It never calls a tool.
- RAG-backed reference agent (`examples/rag_agent`) and a demo MCP server (`examples/mcp_servers`).
- Apache-2.0 license.

## 0.2.0

- Memory-poisoning scenarios (multi-session), model-assisted judge (opt-in), OWASP agentic mapping.
- HTML and Markdown reports, `agentsec replay`, the Python API and the pytest plugin, GitHub Actions annotations and job summary.

## 0.1.0

- Local testing engine: OpenAI-compatible HTTP adapter, YAML policies, seven attack categories, deterministic evaluators, JSON reports.
