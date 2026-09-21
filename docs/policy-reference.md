# Policy reference

A policy is a YAML file, `agentsec.yaml` by default. It says what the agent may do and how AgentSec
should test it. Unknown keys are rejected so typos are caught. Machine-readable schema: `agentsec schema policy`.

## Full example

```yaml
version: "1"

agent:
  name: support-agent
  endpoint: http://localhost:8000/v1/chat/completions
  model: agentsec-target
  api_key_env: SUPPORT_AGENT_TOKEN
  headers:
    X-Env: test
  timeout_s: 30
  declare_tools: true
  retrieval_tools: [search_documents]
  pricing:
    input_per_1k: 0.003
    output_per_1k: 0.015

allowed_tools: [search_documents, create_draft]
forbidden_actions: [send_email, reveal_credentials, execute_payment]

secrets:
  - sk-live-EXAMPLE-DO-NOT-USE-REAL-KEYS
  - env:DB_TEST_PASSWORD

limits:
  max_steps: 12
  max_tool_calls: 10
  max_repeated_calls: 3
  max_tokens: 20000
  max_seconds: 120
  max_cost_usd: 0.50

tests:
  - prompt_injection
  - indirect_prompt_injection
  - secret_extraction
  - unauthorized_tool_use
  - tool_output_poisoning
  - unsafe_retrieved_documents
  - loop_and_budget_limits
  - memory_poisoning

# Optional: model-assisted checks, used only with `agentsec test --judge`
judge:
  endpoint: http://localhost:11434/v1/chat/completions
  model: my-local-judge
  checks: [goal_hijack, paraphrased_leak]
  min_confidence: 0.7
  severity: medium
```

## Top-level keys

| Key | Required | Default | Meaning |
|---|---|---|---|
| `version` | no | `"1"` | Policy schema version. Only `"1"` is supported |
| `agent` | yes | | How to reach the agent |
| `allowed_tools` | no | none | Tools the agent may call. If omitted, no allowlist is enforced. If set to `[]`, any tool call is a violation |
| `forbidden_actions` | no | `[]` | Actions that must never be attempted. Also used as the names in attack payloads |
| `secrets` | no | `[]` | Values that must never appear in agent output. Use synthetic credentials only |
| `limits` | no | see below | Operating budgets |
| `tests` | no | all categories | Which attack categories to run |
| `judge` | no | none | Optional model-assisted evaluation. See [`judge`](#judge) |

## `agent`

| Key | Default | Meaning |
|---|---|---|
| `name` | required | Label used in reports |
| `endpoint` | required | Full URL that receives POST requests. Must start with `http://` or `https://` |
| `model` | `agentsec-target` | Sent as `model` in each request |
| `api_key_env` | none | Name of an environment variable holding a bearer token. The value is never stored in the policy or the report |
| `headers` | `{}` | Extra HTTP headers |
| `timeout_s` | `30` | Per-request timeout. A timeout counts as an adapter error for that scenario |
| `declare_tools` | `true` | Advertise allowed tools and forbidden decoys in each request. Set `false` for agents that manage their own tools |
| `retrieval_tools` | `[]` | Tools whose results carry adversarial content. If empty, every allowed tool does |
| `pricing` | none | `input_per_1k` and `output_per_1k`, used to compute cost from token usage when the agent does not report cost |

## `limits`

| Key | Default | Enforced |
|---|---|---|
| `max_steps` | 12 | Live. Model calls per scenario |
| `max_tool_calls` | 10 | Live. The call that would exceed it is recorded and not executed |
| `max_repeated_calls` | 3 | After the run. Identical tool calls with the same arguments |
| `max_tokens` | none | After the run. Total prompt and completion tokens the agent reports |
| `max_seconds` | none | Live, between steps, and again after the run |
| `max_cost_usd` | none | After the run, when cost is known |

Integer limits must be whole numbers of at least 1. Seconds and cost must be at least 0.

## `secrets`

Each entry is either a literal value or `env:NAME`, which is read from your environment at run time.
Unset variables are skipped. Secrets are never written to reports. The policy section of `report.json`
records only how many there were. Any secret found in output is masked in the report as its first four
and last two characters.

Besides your list, AgentSec also flags common credential formats in output: AWS access keys, `sk-` API keys,
GitHub tokens, private key headers and long bearer tokens.

## `tests`

Valid categories: `prompt_injection`, `indirect_prompt_injection`, `secret_extraction`, `unauthorized_tool_use`,
`tool_output_poisoning`, `unsafe_retrieved_documents`, `loop_and_budget_limits`, `memory_poisoning`. Leaving `tests` empty runs all
of them. Anything else is an error that lists the valid names.

Drop `memory_poisoning` from the list if your agent has no long-term memory: it passes trivially, but it doubles the requests for those scenarios.

## `judge`

Optional and off by default. The section is only read when you run `agentsec test --judge`. See [Judge](judge.md) for what it does and what it sends.

| Key | Default | Meaning |
|---|---|---|
| `endpoint` | required | OpenAI-compatible chat-completions URL of the judge model |
| `model` | `judge` | Sent as `model` |
| `api_key_env` | none | Environment variable holding a bearer token |
| `headers` | `{}` | Extra HTTP headers |
| `timeout_s` | `60` | Per-request timeout |
| `checks` | both | `goal_hijack`, `paraphrased_leak` |
| `min_confidence` | `0.7` | Verdicts below this confidence are ignored. Between 0 and 1 |
| `severity` | `medium` | Severity given to judge findings: `low`, `medium` or `high`. `critical` is not allowed |

## Tips for choosing values

- List every tool your agent really has in `allowed_tools`. The allowlist check only runs when the key is present.
- Put dangerous but real actions in `forbidden_actions`. Their names are used in attack payloads, so use the actual names your agent would recognise.
- Give the agent a synthetic secret in its environment or system prompt, and list the same value under `secrets`.
  Without it, secret extraction can only catch credential-shaped strings.
- Set `retrieval_tools` if only some tools return untrusted content, so writes like `create_draft` are not fed attack payloads.
- Step and tool-call limits apply to each conversation, so a memory scenario gets a fresh budget for its follow-up.
- Keep limits realistic for the agent's normal behavior. A limit set below what a healthy task needs will produce findings on benign runs.
