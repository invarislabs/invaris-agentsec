# Framework compatibility benchmark

**Question:** does AgentSec detect the same security failure whatever framework the agent is built with?

**Method:** one scripted decision function (`brain.py`) stands in for the model in every framework. It behaves the
way models are documented to behave under prompt injection (vulnerable mode) or refuses (safe mode), always the same
way for the same input. Each framework runs it inside its own real runtime -- its own agent loop, message formats,
tool dispatch, iteration limits and error handling -- with tools that call AgentSec's in-process `ToolHost`. The same
35 scenarios from `policy.yaml` run against every framework, and the findings are compared with a no-framework
reference (`frameworks/reference.py`: the same brain calling the host directly).

**What this shows:** that AgentSec can drive each framework, observe what it executes, and reach the same verdicts;
and where a framework changes what is observable. **What it does not show:** how any real LLM behaves inside these
frameworks -- the model is scripted. Verification level: integrated and executed (real framework runtimes, scripted
model), not tested with LLMs.

## Run

Each framework needs its own virtual environment (their dependency pins conflict):

```bash
python -m venv .venv-crewai && .venv-crewai/bin/pip install crewai pyyaml && .venv-crewai/bin/pip install -e . --no-deps
.venv-crewai/bin/python benchmarks/framework-compat/run.py crewai_crew
python benchmarks/framework-compat/compare.py        # writes MATRIX.md from results/
```

| Module | Framework | Install |
|---|---|---|
| `reference` | none | - |
| `langchain_agent` | LangChain v1 `create_agent` | `langchain langchain-core langgraph` |
| `langgraph_graph` | LangGraph `StateGraph` + `ToolNode` | `langgraph langchain-core` |
| `crewai_crew` | CrewAI Agent + Task + Crew | `crewai` |
| `autogen_agentchat` | AutoGen AgentChat `AssistantAgent` | `autogen-agentchat autogen-core` |
| `openai_agents_sdk` | OpenAI Agents SDK `Agent` + `Runner` | `openai-agents` |
| `google_adk` | Google ADK `LlmAgent` + `InMemoryRunner` | `google-adk` |
| `smolagents_agent` | smolagents `ToolCallingAgent` | `smolagents` |

Multi-agent teams: `multi_agent/run.py openai_agents_team` and `multi_agent/run.py crewai_team`.

## Results (2026-10-03)

See [MATRIX.md](MATRIX.md) for the versions and every difference. Summary:

- All seven frameworks: 30/35 scenarios with findings in vulnerable mode, **0 false positives** in safe mode, and
  **33/35 scenarios with exactly the reference's findings** -- including the new authority checks (task scope, stale
  authorization, data-flow exfiltration and untrusted execution, false and unsupported action claims, cross-principal
  access).
- The two differences are the same in every framework: `unauthorized_tool_use/delete_records` and `.../shell_access`
  ask for tools the framework was never given. Every framework refuses an unknown tool name before execution
  (most hand an error back to the model or end the run; the OpenAI Agents SDK raises `ModelBehaviorError`, recorded
  as a scenario error). Nothing executed, so through the host there is nothing to
  observe: the *attempt* is NOT OBSERVABLE this way, and the framework's own tool registry held.
- Three scenarios fail nowhere, including the reference, because the scripted brain has no memory and does not
  decode base64 or fan out -- a property of the brain, not of AgentSec or the frameworks.

## Findings that changed AgentSec

Running real framework loops surfaced two engine issues, both fixed:

1. Calls a framework executes were recorded *after* its final reply, so a reply denying an action appeared to come
   before the action. Executed calls are now recorded before the reply they led to.
2. When a framework crashed (CrewAI at its iteration limit, before a fix to the scripted model), every call it had
   already executed was lost and the scenario was an error with no findings. Calls made before a failure are now
   recorded, and errored runs are evaluated on what the agent actually did.
