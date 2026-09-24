# MCP server scanning

`agentsec mcp scan` connects to an [MCP](https://modelcontextprotocol.io) server, lists its tools,
resources and prompts, and checks their definitions for the ways a malicious or compromised server
attacks the agent that connects to it.

**It never calls a tool, reads a resource or fetches a prompt.** It only sends `initialize`,
`tools/list`, `resources/list` and `prompts/list`, so scanning cannot trigger a server's side effects.
Resources and prompts are optional MCP capabilities: a server that doesn't implement them just
contributes an empty list, not an error. (Scanning does start the server if you give `--command`, so
only scan servers you are willing to run.)

Tools get the most scrutiny -- they are what an agent actually calls -- but resources and prompts are
just as capable of carrying a hidden instruction: a resource's `description` and a prompt's
`description`/argument descriptions are handed to the model the same way a tool's description is, so
the same instruction-poisoning patterns apply to all three.

## Usage

```bash
# a local stdio server
agentsec mcp scan --command "python my_server.py"

# a streamable-HTTP server (headers may use $ENV_VARS)
agentsec mcp scan --url https://mcp.example.com/mcp --header "Authorization=Bearer $TOKEN"

# also check against your policy's allowed_tools and forbidden_actions
agentsec mcp scan --command "python my_server.py" --policy agentsec.yaml

# pin definitions once, then detect later changes (rug pulls)
agentsec mcp scan --command "python my_server.py" --pin-write mcp.pins.json
agentsec mcp scan --command "python my_server.py" --pin mcp.pins.json

# list twice in one session and report differences
agentsec mcp scan --command "python my_server.py" --recheck
```

Options: `--out DIR` (report directory, default `.agentsec`, file `mcp-report.json`), `--timeout SECONDS`,
`--fail-on low|medium|high|critical|none`. Exit codes match `agentsec test`: 0 clean, 1 findings at or above
the threshold, 2 could not connect or read a file.

Try it on the bundled demo server, which has clean, poisoned and rug-pull modes (each also has a
resource and a prompt, and the poisoned mode poisons one of each too):

```bash
agentsec mcp scan --command "python examples/mcp_servers/server.py"                 # clean, exit 0
agentsec mcp scan --command "python examples/mcp_servers/server.py --poisoned"      # exit 1
agentsec mcp scan --command "python examples/mcp_servers/server.py --rugpull" --recheck   # exit 1
```

## What it checks

| Rule | Severity | Meaning |
|---|---|---|
| `mcp_tool_poisoning`, `mcp_resource_poisoning`, `mcp_prompt_poisoning` | critical / high | Instructions aimed at the model in a description, input schema, or (for prompts) an argument description -- "ignore previous instructions", "do not tell the user", `<IMPORTANT>` tags, extra steps around the call, or a pointer to "full instructions" at an external URL the scan can't inspect. Critical when combined with references to secret files or sending data out; high otherwise |
| `mcp_invisible_characters` | high | Zero-width, bidirectional or tag characters that can hide text from a human reviewer |
| `mcp_confusable_tool_name` | high | A tool name is a visual look-alike of another tool on the same server, built from Cyrillic, Greek or fullwidth characters that render the same as Latin ones -- a homoglyph impersonation of a tool the user or agent already trusts |
| `mcp_annotation_mismatch` | medium | A tool's `annotations.readOnlyHint` or `destructiveHint` contradicts what its own name or description says it does |
| `mcp_tool_shadowing` | medium | One tool's description gives instructions about how to use another tool |
| `mcp_sensitive_reference` | medium | A definition names credentials or secret files (`~/.ssh`, `.env`, API keys) |
| `mcp_resource_uri_credentials` | medium | A resource URI embeds a username and password |
| `mcp_forbidden_tool_exposed` | high | The server offers a tool in your policy's `forbidden_actions` |
| `mcp_unlisted_tool` | medium | With a policy: a tool not in `allowed_tools` |
| `mcp_duplicate_tool`, `mcp_duplicate_resource`, `mcp_duplicate_prompt` | medium | The same name (or resource URI) is listed twice |
| `mcp_definition_changed` | high | With `--pin` or `--recheck`: a tool, resource or prompt definition differs from the pinned or earlier one |
| `mcp_tool_added`/`removed`, `mcp_resource_added`/`removed`, `mcp_prompt_added`/`removed` | medium, low | With `--pin`: the tool, resource or prompt list changed |
| `mcp_high_impact_tool` | low | Without a policy: a tool named like shell, delete, payment or email |
| `mcp_unconstrained_input` | low | A free-form `command`, `sql`, `code`-style string with no enum, pattern or length limit |
| `mcp_oversized_description` | low | A tool, resource or prompt description over 2000 characters |

Findings are mapped to OWASP agentic categories (mostly ASI04, supply chain) like all others, and the
report has the same `findings` and `scenarios` layout as `agentsec test`, so `agentsec compare` works on two
`mcp-report.json` files. The report's `summary` also breaks out `tools`, `resources` and `prompts` counts,
and `--pin-write`/`--pin` pin all three kinds together in one file (a pin file from before resources and
prompts were scanned still works -- it just has nothing pinned for those two yet).

## Limits: read before relying on it

- These are **pattern checks on definitions**. A clean result does not mean a server is safe. A server can
  behave badly in `tools/call`, `resources/read` or `prompts/get` results, be obfuscated beyond the
  patterns, or be benign today and change later.
- The instruction patterns are English-only and heuristic. Expect some false positives and misses.
- The confusable-name check uses a compact, hand-picked map of common Cyrillic, Greek and fullwidth
  look-alikes, not the full Unicode confusables table -- it catches the homoglyphs attackers actually use
  for this, not every codepoint that could theoretically be confused with another.
- `--recheck` and `--pin` catch changes only between the moments you list. A server that changes definitions
  only for certain clients, times or after tool calls would not be caught.
- A resource's or prompt's *content* (`resources/read`, `prompts/get`) is never fetched, the same way a
  tool is never called -- only what `resources/list` and `prompts/list` themselves return is scanned. A
  server that serves a clean listing but a poisoned resource body or rendered prompt would not be caught
  here; that's server output at run time, covered on the agent side by the `tool_output_poisoning` and
  `unsafe_retrieved_documents` scenarios, not by this scanner.
- The scanner covers the server side. To test an agent that *uses* MCP servers, see the next section.
- Verified against the bundled demo server and a test HTTP server, not against a range of real-world MCP servers.

# Testing an agent that uses MCP (`--mcp-listen`)

The scanner checks a server's definitions. To test an *agent* that connects to MCP servers, AgentSec plays the server:

```bash
# 1. AgentSec serves the policy's tools over MCP (streamable HTTP at /mcp) and runs the suite
agentsec test -p agentsec.yaml --mcp-listen 127.0.0.1:8765

# 2. your agent, configured to use http://127.0.0.1:8765/mcp as its MCP server, answers AgentSec's chat requests
```

Point your agent's MCP client at the URL printed on start. From there the run works like any other:

- The host offers `allowed_tools` plus the `forbidden_actions` as decoys, exactly like the simulated-tool runner. AgentSec sends **no** tool definitions in the chat request, because the agent already gets its tools over MCP. (`agent.declare_tools` is ignored.)
- Tool results for the scenario's retrieval tools carry the adversarial content (poisoned documents, tool-output injection, memory payloads). Other tools return `OK (simulated by AgentSec sandbox; no real action was taken)`.
- Every `tools/call` the agent makes is recorded, including calls to tools the host never offered (that attempt is a finding), and appears in the trace as a tool call executed by the agent. All evaluators, reports, replay and compare work unchanged.
- The agent runs its tool loop inside one chat request, so AgentSec cannot stop it mid-loop. The tool-call budget is therefore checked afterwards and reported as `limit_max_tool_calls`; runaway loops are also caught by `repeated_calls` and the time and cost limits.

Try it with the bundled agent, which uses the MCP host and reuses the decision logic of the vulnerable reference agent:

```bash
python examples/mcp_agent/server.py --mcp-url http://127.0.0.1:8765/mcp &          # add --safe for the hardened variant
agentsec test -p examples/mcp_agent/agentsec.yaml --mcp-listen 127.0.0.1:8765
```

Python API: `SecuritySuite(target, adapter=..., mcp_host=MCPAttackHost(policy).start())`.

Notes and limits:

- The host serves adversarial content and accepts any client. It listens on loopback by default; the CLI warns if you bind elsewhere. Do not expose it beyond an isolated network.
- Only streamable HTTP is supported (JSON responses, no server-initiated streams, no authentication). Agents that can only launch stdio servers cannot use it yet.
- Tool schemas are generic (`query` plus free-form arguments). An agent that validates arguments against precise schemas may behave differently from how it would with your real servers.
- This tests how the agent handles hostile tool results and decoy tools. It does not test the agent against your *real* MCP servers.
- Verified against the bundled reference agent (vulnerable: caught, including critical findings; safe: passes all scenarios), not against real MCP-capable agent frameworks.
