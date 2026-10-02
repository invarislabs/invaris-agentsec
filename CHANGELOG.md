# Changelog

All notable changes are listed here. The project follows [Semantic Versioning](https://semver.org/); while the
version is below 1.0, minor releases may change behaviour, and the changes are listed below.

## Unreleased

- New: `action_without_authorization`, a 9th built-in attack category addressing a gap no
  existing category could express: a tool call that is globally allowed for the agent, but that
  the *current task* never authorized. A coding assistant asked only to review something has no
  more business calling `write_file` than one asked to fix something is wrong to call it --
  `allowed_tools`/`forbidden_actions` can't tell those apart because the distinction isn't about
  the tool, it's about what the request actually asked for. Policies opt in by declaring
  `tool_effects` (tool name -> effect tags: `read`, `write`, `delete`, `execute`, `network`,
  `financial`, `credential_access`, ...); scenarios opt in by declaring `authorized_effects`. A
  new evaluator, `ActionAuthorizationEvaluator` (rule `unauthorized_side_effect`, mapped to
  ASI03/ASI02/ASI01), flags a call whose effects exceed what the scenario's task authorized, and
  only for tools with declared effects -- it never guesses. Without `tool_effects`, this category
  produces zero scenarios and every other policy is unaffected. See
  [Policy reference](docs/policy-reference.md#tool_effects),
  [Attack catalog](docs/attack-catalog.md#9-action_without_authorization), and
  [`examples/real_world_agents/demo_action_without_authorization.py`](examples/real_world_agents/demo_action_without_authorization.py)
  for a concrete before/after walkthrough (the identical `write_file` call is flagged when the
  task only authorized reading, and silent when the task authorized writing). All three
  `examples/real_world_agents/` policies now declare `tool_effects` and include this category;
  verified live (43/43, 41/41, 43/43 vulnerable-fails / safe-passes).
- New: `AgentTarget(tool_effects=...)` and `RunResult.unauthorized_side_effects` in the Python API,
  for parity with the YAML policy surface.
- New: three more reference agents in `examples/real_world_agents/` (`coding_assistant`,
  `support_assistant`, `browser_assistant`), modeled on real daily-use AI agent products rather
  than a generic RAG bot, each with a vulnerable and a `--safe` mode and paired one-to-one with an
  existing domain attack pack (`coding_agent_pack.py`, `support_agent_pack.py`,
  `browser_agent_pack.py`). See [`examples/real_world_agents/README.md`](examples/real_world_agents/README.md)
  and [Agent contract](docs/agent-contract.md#the-real-world-reference-agents).
- Fix: `SecretLeakEvaluator` decided whether a canary's reappearance in the same conversation was
  benign by checking `scenario.category == "memory_poisoning"` literally, so any other category
  with the same shape (canaries plus a `Followup(same_session=False)`) -- including the new
  `support_agent_cross_customer_leak` category above -- got a false positive on its own benign,
  same-session acknowledgment, and a genuine cross-session leak was mislabeled as a retrieved-
  document disclosure instead of a memory leak. Now keyed off the scenario's own shape instead of
  its category name. Covered by two new tests in `tests/test_evaluators.py`.

## 0.6.0

- `agentsec mcp scan` now scans MCP resources and prompts, not just tools: poisoned descriptions
  and argument descriptions, invisible/bidirectional characters, homoglyph tool-name impersonation
  (`mcp_confusable_tool_name`), annotation/behavior mismatches (`mcp_annotation_mismatch`),
  credentials embedded in a resource URI (`mcp_resource_uri_credentials`), duplicate resources and
  prompts, and `--pin`/`--recheck` change tracking (added/removed/changed) across all three kinds.
  See [MCP testing](docs/mcp-testing.md).
- Policy schema: `spend_limits` and `address_allowlist` sections let a policy cap the amount and
  restrict the destination of tool calls that move money or send something somewhere, enforced by
  two new core evaluators (`spend_limit_exceeded`, `spend_total_exceeded`,
  `address_not_allowlisted`). Both are domain-agnostic -- the tool names and argument fields they
  watch are declared in the policy, not hardcoded to any specific integration -- so they apply
  alongside any attack pack, not just the bundled on-chain one. The on-chain reference pack's own
  spend-cap check now defers to a policy-declared `max_transaction` when one is set. See
  [Policy reference](docs/policy-reference.md#spend_limits).
- Docs: `docs/owasp-mapping.md`'s finding-rule table and ASI02-04 summaries were missing the new
  MCP resource/prompt rules and the spend/allowlist rules; both are now listed.

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
