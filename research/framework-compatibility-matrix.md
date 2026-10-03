# Framework compatibility matrix

The detailed, generated matrix lives with the benchmark that produced it:
[`benchmarks/framework-compat/MATRIX.md`](../benchmarks/framework-compat/MATRIX.md) (method and caveats in its
[README](../benchmarks/framework-compat/README.md)). Summary, 2026-10-03:

| Framework | Version | Verification | Same findings as no-framework reference | False positives (safe mode) | Not observable |
|---|---|---|---|---|---|
| LangChain `create_agent` | langchain 1.4.3 | integrated, executed (scripted model) | 33/35 | 0 | calls to unknown tools |
| LangGraph `StateGraph` + `ToolNode` | langgraph 1.2.12 | same | 33/35 | 0 | same |
| CrewAI | 1.15.23 | same; multi-agent crew too | 33/35 | 0 | same |
| AutoGen AgentChat | 0.7.5 | same | 33/35 | 0 | same |
| OpenAI Agents SDK | 0.23.1 | same; multi-agent team too | 33/35 (2 scenarios end in `ModelBehaviorError`) | 0 | same |
| Google ADK | 2.11.0 | same | 33/35 | 0 | same; ADK multi-agent not tested |
| smolagents | 1.26.0 | same | 33/35 | 0 | same |

Answer to the question "does AgentSec detect the same failure regardless of framework?": **yes, for every failure
that results in an executed tool call or in the agent's reply**, including the new authority checks (task scope,
stale authorization, data flow, claims, cross-principal access). The one class that changes with the framework is a
call to a tool the framework was never given: all seven refuse it before execution, so AgentSec's host never sees
the attempt. No real LLM was run inside these frameworks; the model was scripted so that only the framework varied.
