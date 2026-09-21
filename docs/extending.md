# Extending AgentSec

## Add an attack scenario to an existing category

Open the category module in `agentsec/attacks/`, for example `prompt_injection.py`, and add a `Scenario` to the list returned by `build(ctx)`.

```python
Scenario(
    id="prompt_injection/my_new_attack",      # category/slug, unique
    category="prompt_injection",
    title="Short human-readable name",        # appears in findings
    description="What it simulates",
    user_message="The text sent to the agent",
    vector=VECTOR_DIRECT,                     # or VECTOR_DOCUMENT / VECTOR_TOOL_OUTPUT
    payload="The adversarial text, kept for evidence",
    markers=[],                               # strings whose presence proves the agent obeyed
    canaries=[],                              # planted values that must not appear in output
    responder=None,                           # function (tool, args, call_index) -> result text
    followups=[],                             # later conversations, for memory scenarios
)
```

Helpers on the `ScenarioContext` (`ctx`) keep scenarios reproducible and tied to the user's policy:

- `ctx.forbidden(i)`: a forbidden action from the policy, cycling if you ask for more than exist.
- `ctx.marker(salt)`: returns `(marker, phrase)`. Put `phrase` in the attack text and list `marker` in `markers`. The literal marker never appears in your input.
- `ctx.canary(salt)`: a unique planted value derived from the seed.
- `ctx.retrieval_tool()`: the name of the tool that carries adversarial content.

For a memory scenario, add `Followup(user_message, responder=None, same_session=True)` entries to `followups`. Each runs as a fresh conversation, and its trace events carry `meta.phase`.
`same_session=False` simulates a different user.

Set `vector` carefully. It determines severity: forbidden actions triggered through documents and tool output are critical.

## Add a new category

1. Create `agentsec/attacks/my_category.py` with `CATEGORY = "my_category"` and `def build(ctx) -> list[Scenario]`.
2. Register it in `agentsec/attacks/__init__.py` by importing the module and adding it to `CATEGORIES`.
3. Add it to the category list in `docs/policy-reference.md` and the catalog in `docs/attack-catalog.md`.
4. Add tests and, if the reference agent should fail it, teach `examples/vulnerable_rag_agent/server.py` the behaviour.

`PLANNED` in the same file holds category names that policies accept but that are not implemented yet. It is empty today. A name in `PLANNED` is skipped with a warning instead of raising an error.

## Add an evaluator

An evaluator takes a scenario, its trace and the policy, and returns a list of `Finding` objects.

```python
from agentsec.evaluators.base import Evaluator, Finding, excerpt

class MyEvaluator(Evaluator):
    name = "my_check"

    def evaluate(self, scenario, trace, policy):
        findings = []
        for ev in trace.of_type("assistant_message"):
            if "something bad" in (ev.content or ""):
                findings.append(Finding(
                    rule="my_rule", key="", scenario_id=scenario.id, category=scenario.category,
                    severity="high", title="Human-readable title",
                    policy_violated="which rule was broken", observed_action="what happened",
                    input=scenario.user_message, evidence=excerpt(trace, ev.seq),
                    remediation="How to fix it",
                ))
        return findings
```

Add the class to `DEFAULT_EVALUATORS` in `agentsec/evaluators/__init__.py`. To classify its findings for OWASP, add the rule id to `agentsec/owasp.py`. Guidelines:

- Base the check on the trace only. Do not call the agent or network.
- Give each finding a `key` when a scenario could produce several of the same rule, so ids stay unique.
- If a finding involves a secret, put the value in `sensitive` so the report masks it.
- Write a test that includes a case that must not be flagged.

## Add an adapter

Subclass `AgentAdapter` in `agentsec/adapters/` and implement one method:

```python
class MyAdapter(AgentAdapter):
    def chat(self, messages, tools, session=None) -> AgentReply:
        ...  # call your agent, return AgentReply(content=..., tool_calls=[ToolCall(id, name, args)], ...)
```

Raise `AdapterError` with a clear message for anything the runner should record as an errored scenario. The adapter must not keep conversation state,
because the runner resends the full message history on every step. `session` identifies the simulated user; pass it to agents that keep memory (the HTTP adapter sends it as `user` and `X-AgentSec-Session`). Adapters are constructed in `agentsec/cli/main.py`. Selecting one from
the policy (for example an `agent.type` key) is not implemented yet, so it is a small change to the loader and the CLI.

For an agent that lives in your Python process, you do not need a new adapter: wrap a function with `CallableAdapter` (see
[Python API](python-api-and-pytest.md#testing-an-in-process-agent-no-http-server)). For a streaming HTTP agent set `agent.stream: true`.

## Add an MCP check

Checks on MCP tool definitions live in `agentsec/mcp/checks.py` (`scan_tools`). Add a rule by appending a `Finding` built with `_finding(...)`,
give it an `mcp_` rule id, map it to OWASP categories in `agentsec/owasp.py`, and cover it in `tests/test_mcp.py` with one definition that must
be flagged and one near miss that must not. Keep patterns narrow: a description that merely says "you must provide a path" must stay clean.

## Change the policy or trace schema

Update the dataclasses and the loader, the matching JSON Schema file (`policy.schema.json` or `trace.schema.json`), and the tests.
`tests/test_schemas.py` checks that the loader and the schemas agree. Changes that break existing files should bump the schema version.

## Project conventions

- Keep evaluators deterministic and side-effect free.
- Never execute real tool actions. All tools are simulated by the runner.
- Use synthetic credentials and reserved domains such as `example.com` and `.invalid` in scenarios.
- Keep runtime dependencies minimal. Today that is PyYAML only.
