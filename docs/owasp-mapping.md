# OWASP mapping

Every finding carries an `owasp` list naming the closest categories of the
[OWASP Top 10 for Agentic Applications (2026)](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/).
The JSON report also counts findings per category (`summary.by_owasp`), and the HTML report shows a coverage table.

**This mapping is Invaris' judgement of the closest fit. It is not an official OWASP classification**, and some findings could reasonably be filed elsewhere.
A finding can map to more than one category.

## The categories

| ID | Name | Covered by AgentSec today |
|---|---|---|
| ASI01 | Agent Goal Hijack | Yes: prompt injection, indirect injection, tool-output poisoning, memory poisoning |
| ASI02 | Tool Misuse | Yes: forbidden and out-of-allowlist calls, tool-call, token, time and cost budgets |
| ASI03 | Identity & Privilege Abuse | Partly: leaked credentials and secrets, calls outside the allowlist |
| ASI04 | Agentic Supply Chain Vulnerabilities | Partly: `agentsec mcp scan` checks MCP tool definitions for poisoning and changes |
| ASI05 | Unexpected Code Execution | No |
| ASI06 | Memory & Context Poisoning | Yes: the `memory_poisoning` category |
| ASI07 | Insecure Inter-Agent Communication | No (multi-agent testing is on the roadmap) |
| ASI08 | Cascading Failures | Partly: non-terminating and repeating loops |
| ASI09 | Human-Agent Trust Exploitation | No |
| ASI10 | Rogue Agents | No |

## Finding rules

| Rule | Categories |
|---|---|
| `forbidden_action` | ASI02, plus ASI01 when the scenario is an injection or poisoning attack |
| `unauthorized_tool` | ASI02, ASI03, plus ASI01 in injection and poisoning scenarios |
| `secret_leak` | ASI03. In memory scenarios: ASI06, ASI03 |
| `injection_followed` | ASI01 |
| `memory_poisoned` | ASI06, ASI01 |
| `repeated_calls` | ASI08 |
| `limit_max_steps` | ASI08 |
| `limit_max_tool_calls`, `limit_max_tokens`, `limit_max_seconds`, `limit_max_cost_usd` | ASI02 |
| `judge_goal_hijack` | ASI01 |
| `judge_paraphrased_leak` | ASI03 |
| `mcp_tool_poisoning`, `mcp_invisible_characters` | ASI04, ASI01 |
| `mcp_tool_shadowing` | ASI04, ASI02 |
| `mcp_definition_changed`, `mcp_tool_added`, `mcp_tool_removed`, `mcp_duplicate_tool`, `mcp_oversized_description` | ASI04 |
| `mcp_sensitive_reference` | ASI03, ASI04 |
| `mcp_forbidden_tool_exposed`, `mcp_high_impact_tool` | ASI02 |
| `mcp_unlisted_tool` | ASI02, ASI03 |
| `mcp_unconstrained_input` | ASI05 |

A rule the table does not know maps to no category, and the finding has an empty `owasp` list.

## Changing the mapping

The mapping lives in `agentsec/owasp.py` (`_BY_RULE` and the two adjustments in `map_finding`). Add your rule id there when you add an evaluator.
`tests/test_reports_phase2.py` checks that every rule the reference agents can trigger is mapped.
