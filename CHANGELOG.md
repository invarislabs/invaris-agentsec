# Changelog

All notable changes are listed here. The project follows [Semantic Versioning](https://semver.org/); while the
version is below 1.0, minor releases may change behaviour, and the changes are listed below.

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
