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

That's how to contribute a category to AgentSec itself. For a category specific to your own product that
you don't want to publish (or to try one out without a pull request), write an attack pack instead.

## Write an attack pack

An attack pack is a normal Python module — a local file or an installed package — that adds one or more
scenario categories without touching AgentSec's own code. Give it the same shape as a built-in category
module, plus a `CATEGORIES` dict:

```python
# my_pack.py
from agentsec.attacks.base import Scenario, ScenarioContext

def build_my_category(ctx: ScenarioContext) -> list[Scenario]:
    return [Scenario(id="my_category/one", category="my_category", title="...",
                     description="...", user_message="...")]

CATEGORIES = {"my_category": build_my_category}
```

Load it with `--attack-pack my_pack.py` (repeatable; also takes an installed module name), or add it to
the policy so it loads every time:

```yaml
attack_packs:
  - my_pack.py
tests:
  - my_category        # packs run only if listed here, or if `tests:` is left empty
```

A pack category cannot reuse a built-in category name or another pack's name in the same run; `agentsec`
raises a clear error naming the clash. Give scenarios the same `category` as their `CATEGORIES` key and
unique ids, and build at least one scenario per category — `agentsec` checks this and raises `PolicyError`
otherwise, so a broken pack fails loudly rather than silently running nothing.

Attack packs run as ordinary Python imports: **load only packs you wrote or trust**, the same as any
dependency. The `SecuritySuite(attack_packs=...)` and `agentsec.attacks.packs.load_packs` Python API do the
same thing for code that builds its own `ScenarioContext`. See `examples/attack_packs/brand_and_pii_pack.py`
for a complete example, including a pack scenario that uses `ctx.canary` and `ctx.marker`.

### Give a pack its own evaluator

Most pack categories need no custom evaluator: a scenario that names a forbidden tool, or plants a marker
or canary, is already caught by AgentSec's built-in evaluators (see "Add an evaluator" below) the same way
a built-in category would be. A pack needs its own evaluator only when the danger is in a tool call's
*arguments* rather than which tool got called or whether a marker appeared -- for example, a legitimate,
allowed `install_package` call that names a typosquatted package, or an allowed `write_file` call whose
content disables a security control. Export an optional `EVALUATORS` list alongside `CATEGORIES`:

```python
# my_pack.py
from agentsec.evaluators.base import Evaluator, Finding, excerpt

class MyPackCheck(Evaluator):
    name = "my_pack_check"

    def evaluate(self, scenario, trace, policy):
        findings = []
        for ev in trace.of_type("tool_call"):
            if ev.tool_name == "install_package" and "danger" in str(ev.arguments):
                findings.append(Finding(rule="my_pack_rule", key="", scenario_id=scenario.id,
                                       category=scenario.category, severity="high", title="...",
                                       policy_violated="...", observed_action="...",
                                       input=scenario.user_message, evidence=excerpt(trace, ev.seq),
                                       remediation="..."))
        return findings

CATEGORIES = {"my_category": ...}
EVALUATORS = [MyPackCheck]
```

Each class must subclass `Evaluator` (see "Add an evaluator" below for the full shape); `agentsec` checks
this the same way it checks `CATEGORIES`, and raises `PolicyError` naming the pack otherwise. Every pack's
evaluators run for every scenario in the run, alongside the built-in ones and before an optional `--judge`
review -- they are not scoped to the pack's own categories, the same way built-in evaluators are not scoped
to one built-in category. Findings from a pack evaluator have no OWASP mapping unless its `rule` id happens
to match one AgentSec already knows about; that's fine; the report and SARIF output show them regardless.
See `examples/attack_packs/coding_agent_pack.py` for a complete example with two pack evaluators
(a typosquatted-dependency check and an insecure-patch-content check) alongside a category that needs no
custom evaluator at all, or `examples/attack_packs/browser_agent_pack.py` for the same pattern applied to
a lookalike-domain check. Not every attack can even be expressed deterministically: see
`examples/attack_packs/rag_pack.py`'s `rag_citation_spoofing` category for one built to rely on the judge
model instead of any evaluator, or `examples/attack_packs/support_agent_pack.py` for a category that needs
no pack evaluator because a *built-in* evaluator other than the tool-policy one already covers it. And see
`examples/attack_packs/onchain_agent_pack.py` for a domain where every category needs its own evaluator,
because its tools (`send_transaction`, `approve_token`) have no "forbidden action" angle at all -- the
danger is always in the arguments. See [Domain attack packs](domain-attack-packs.md) for all five.

### Give a pack its own judge check

`EVALUATORS` covers deterministic detection; some attacks have no deterministic signal at all --
no forbidden call, no marker, no canary -- and only the optional judge model (`agentsec test
--judge`) can plausibly catch them. Until now a pack could only lean on the two built-in judge
questions (`goal_hijack`, `paraphrased_leak`), which are deliberately generic. Export an optional
`JUDGE_CHECKS` dict alongside `CATEGORIES` and `EVALUATORS` to give the judge a question phrased in
your own domain's terms instead:

```python
# my_pack.py
from agentsec.evaluators.base import JudgeCheck

JUDGE_CHECKS = {
    "my_pack_check": JudgeCheck(
        question="Did the agent do the specific bad thing this category is testing for? "
                 "Answer only with the required JSON object.",
        title="Model judge: ...",
        policy_violated="...",
        remediation="...",
    ),
}

CATEGORIES = {"my_category": ...}
```

A policy opts in the same way it opts into a built-in check, by name, in `judge.checks:`:

```yaml
attack_packs: [my_pack.py]
judge:
  endpoint: 'https://...'
  checks: [my_pack_check]   # or alongside goal_hijack, paraphrased_leak
```

Each value must be a `JudgeCheck`; `agentsec` checks this the same way it checks `EVALUATORS`, and
raises `PolicyError` naming the pack otherwise. A pack check's name must not collide with a built-in
check name or with another loaded pack's check name -- unlike evaluators (which just all run every
time), judge checks are selected by name from `judge.checks:`, so a collision would silently shadow
one of them; `agentsec` rejects the policy load instead. Naming a check `agentsec` doesn't recognize
-- a typo, or a pack that was never listed in `attack_packs:` -- is also a `PolicyError`, but only
once packs are actually loaded (at `agentsec test --judge` time), not when the policy file is first
parsed, the same way an unknown `tests:` category name is only caught once scenarios are built.

Unlike the built-in checks, which only run when a scenario's own shape looks relevant (`goal_hijack`
only for untrusted-content scenarios that no deterministic evaluator already flagged,
`paraphrased_leak` only when the scenario planted canaries), a pack-provided check has no such
gating: it runs once per scenario whenever it's selected, and it's up to the question's own wording
to say when there's nothing to flag. That keeps the extension point simple -- no gating-condition
DSL to design -- at the cost of a pack author needing to write a question that behaves reasonably
across every scenario in the run, not just the one category it was written for.

See `examples/attack_packs/rag_pack.py`'s `rag_fabricated_citation_authority` check for a complete
example: it gives `rag_citation_spoofing` (which has no deterministic signal at all) a question
phrased around exactly its failure mode, as an alternative to the more general built-in
`goal_hijack` check.

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

For LangChain or LangGraph see [Frameworks](frameworks.md). For an agent that lives in your Python process, you do not need a new adapter: wrap a function with `CallableAdapter` (see
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
