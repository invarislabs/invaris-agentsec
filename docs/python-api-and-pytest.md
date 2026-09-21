# Python API and pytest

Everything the CLI does is also available from Python, and a pytest plugin turns scenarios into tests.

## Python API

```python
from agentsec import AgentTarget, SecuritySuite

target = AgentTarget(
    endpoint="http://localhost:8000/agent",
    allowed_tools={"search_documents", "create_draft"},
    forbidden_tools={"send_email", "execute_payment"},
    secrets=["sk-live-EXAMPLE-DO-NOT-USE-REAL-KEYS"],
)

result = SecuritySuite(target).run("indirect_prompt_injection")

assert result.secret_leaks == []
assert result.forbidden_tool_calls == []
assert result.total_tool_calls <= 10
result.assert_clean(fail_on="high")
```

The API may still change before a stable release.

### `AgentTarget`

Describes the agent. It is the same information as an `agentsec.yaml` policy, and it builds a `Policy` (available as `target.policy`).

| Argument | Meaning |
|---|---|
| `endpoint` | Agent URL (required, `http://` or `https://`) |
| `allowed_tools` | Tools the agent may call. Omit for no allowlist |
| `forbidden_tools` | Actions that must never be attempted (the policy's `forbidden_actions`) |
| `secrets` | Values that must never appear in output |
| `name`, `model`, `api_key_env`, `headers`, `timeout_s`, `declare_tools`, `retrieval_tools`, `pricing` | As in the [policy reference](policy-reference.md#agent) |
| `max_steps`, `max_tool_calls`, `max_repeated_calls`, `max_tokens`, `max_seconds`, `max_cost_usd` | As in `limits` |
| `judge` | An optional `JudgeConfig`, used when the suite is created with `judge=True` |

Two constructors load an existing policy: `AgentTarget.from_file("agentsec.yaml")` and `AgentTarget.from_policy(policy)`.

### `SecuritySuite`

```python
SecuritySuite(target, seed=0, adapter=None, judge=False)
suite.run(*names, seed=None)   # -> RunResult
```

`run` takes categories and/or scenario ids (`"prompt_injection"`, `"prompt_injection/marker_override"`). With no names it runs every category. Unknown categories raise
`PolicyError`. The `agentsec.CATEGORIES` list holds all category names.

Pass `adapter=` to test an agent without an HTTP server. Any `AgentAdapter` works, which is handy for testing an agent in the same process:

```python
from agentsec.adapters import AgentAdapter, AgentReply

class MyAgentAdapter(AgentAdapter):
    def chat(self, messages, tools, session=None):
        text = my_agent.respond(messages)          # your code
        return AgentReply(content=text)

result = SecuritySuite(target, adapter=MyAgentAdapter()).run("prompt_injection")
```

### `RunResult`

| Attribute | Meaning |
|---|---|
| `findings` | All findings. Each has `severity`, `title`, `rule`, `scenario_id`, `evidence` and more |
| `secret_leaks` | Findings with the `secret_leak` rule |
| `forbidden_tool_calls` | Every call to a forbidden action, as `ToolCallRecord(scenario_id, name, arguments)` |
| `unauthorized_tool_calls` | Calls to tools outside the allowlist (empty if no allowlist) |
| `total_tool_calls` | The most tool calls any **single scenario** made. Compare it with your `max_tool_calls` |
| `tool_calls_by_scenario` | Call counts per scenario id |
| `errors` | Scenarios that could not run (agent unreachable, invalid reply) |
| `passed` | `True` only if there are no findings **and** no errors |
| `results`, `suite` | Per-scenario results with traces, and the underlying `SuiteResult` |
| `findings_at_least(severity)` | Findings at or above a severity |
| `format(fail_on)` | A readable list of findings and errors |
| `assert_clean(fail_on="low")` | Raises `AssertionError` with that list if a finding at or above `fail_on` exists **or any scenario errored** |

An unreachable agent is never a pass: `passed` is false and `assert_clean` raises.

## pytest plugin

Installing the package registers the plugin through the `pytest11` entry point (reinstall with `pip install -e .` after upgrading a development checkout). No configuration
in `conftest.py` is needed.

```python
# tests/test_agent_security.py
import pytest
from agentsec import CATEGORIES

@pytest.mark.parametrize("category", CATEGORIES)
def test_agent_resists(category, agentsec_run):
    agentsec_run(category, fail_on="high")
```

```bash
pytest --agentsec-policy agentsec.yaml --agentsec-seed 0
```

### Options

| Option | Default | Meaning |
|---|---|---|
| `--agentsec-policy PATH` | `agentsec.yaml` | Policy used by the fixtures |
| `--agentsec-seed N` | `0` | Seed for reproducible scenarios |

### Fixtures

| Fixture | Scope | Provides |
|---|---|---|
| `agentsec_policy` | session | The loaded `Policy`. A bad or missing file fails the test with the loader's message |
| `agentsec_target` | session | An `AgentTarget` built from the policy |
| `agentsec_suite` | session | A `SecuritySuite` using the seed option |
| `agentsec_run` | function | `run(*names, fail_on="low")`: runs scenarios, calls `assert_clean`, and returns the `RunResult` |

The `agentsec` marker is registered for your own use, for example to select these tests with `pytest -m agentsec`.

A failing test shows the findings:

```text
AssertionError: AgentSec: 6 finding(s) at or above 'high', 0 errored scenario(s)
  [CRITICAL] Indirect prompt injection triggered send_email (indirect_prompt_injection/plain_appended)
  ...
```

Each `agentsec_run` call starts a fresh run, so parametrizing over categories runs each category once. Use the CLI if you want the HTML report and OWASP summary. The plugin is for pass or fail gating.

Optional arguments of `SecuritySuite`: `seed`, `adapter`, `judge`, and `mcp_host` (an `MCPAttackHost`, see [MCP testing](mcp-testing.md)).

## Testing an in-process agent (no HTTP server)

Wrap any Python function with `CallableAdapter` and pass it to `SecuritySuite`. This works with any
framework, because you write the few lines that call your agent; AgentSec has no framework integrations of its own.

```python
from agentsec.api import AgentTarget, SecuritySuite
from agentsec.adapters import CallableAdapter

def my_agent(messages, tools):          # (messages), (messages, tools) or (messages, tools, session)
    answer = run_my_framework_agent(messages)
    return {"content": answer.text,
            "executed": [{"name": c.name, "arguments": c.args, "result": c.output} for c in answer.tool_calls]}

target = AgentTarget("http://in-process",           # placeholder; never contacted
                     allowed_tools=["search_documents"], forbidden_tools=["send_email"],
                     declare_tools=False)
result = SecuritySuite(target, adapter=CallableAdapter(my_agent)).run("prompt_injection")
result.assert_clean()
```

The function may return a string, a dict (`content`, `tool_calls`, `executed`, `cost_usd`, `prompt_tokens`,
`completion_tokens`) or an `AgentReply`. If it raises, that scenario is recorded as an error, not a pass.
