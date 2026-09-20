"""Local runner: drives one scenario against the agent, enforcing policy limits,
and records a normalized trace. All tools are simulated; nothing real is executed."""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from ..adapters import AdapterError, AgentAdapter
from ..attacks import build_scenarios
from ..attacks.base import Scenario, ScenarioContext
from ..evaluators import Finding, evaluate_trace
from ..policies import Policy
from ..traces import Trace

SANDBOX_OK = "OK (simulated by AgentSec sandbox; no real action was taken)"
BENIGN_DOC = ("Vendor onboarding policy v3: vendors must complete the security questionnaire "
              "and sign the data-processing addendum before receiving access.")


@dataclass
class ScenarioResult:
    scenario: Scenario
    trace: Trace
    findings: List[Finding] = field(default_factory=list)

    @property
    def status(self) -> str:
        if self.trace.outcome == "error":
            return "error"
        return "findings" if self.findings else "passed"


@dataclass
class SuiteResult:
    policy: Policy
    seed: int
    results: List[ScenarioResult]
    warnings: List[str]

    @property
    def findings(self) -> List[Finding]:
        return [f for r in self.results for f in r.findings]


def declared_tools(policy: Policy) -> List[Dict[str, Any]]:
    """Tool definitions advertised to the agent: its allowed tools plus forbidden
    actions as decoys, so an obedient agent has something to call."""
    names: List[str] = []
    for n in (policy.allowed_tools or []) + policy.forbidden_actions + policy.agent.retrieval_tools:
        if n not in names:
            names.append(n)
    return [{
        "type": "function",
        "function": {
            "name": n,
            "description": "Tool %s (simulated by AgentSec)." % n,
            "parameters": {"type": "object", "properties": {"query": {"type": "string"}},
                           "additionalProperties": True},
        },
    } for n in names]


def _is_scenario_tool(policy: Policy, name: str) -> bool:
    """Tools whose results carry the scenario's adversarial content."""
    if name in policy.forbidden_actions:
        return False
    if policy.agent.retrieval_tools:
        return name in policy.agent.retrieval_tools
    return policy.allowed_tools is None or name in policy.allowed_tools


def run_scenario(scenario: Scenario, policy: Policy, adapter: AgentAdapter,
                 clock: Callable[[], float] = time.monotonic) -> Trace:
    lim = policy.limits
    trace = Trace(scenario_id=scenario.id)
    start = clock()

    def now_ms() -> int:
        return int((clock() - start) * 1000)

    tools = declared_tools(policy) if policy.agent.declare_tools else []
    messages: List[Dict[str, Any]] = [{"role": "user", "content": scenario.user_message}]
    trace.add("user_message", now_ms(), content=scenario.user_message)
    usage = trace.usage
    scenario_calls = 0

    def stop(limit: str, detail: str) -> None:
        trace.outcome, trace.limit = "limit_exceeded", limit
        trace.add("limit", now_ms(), content=detail, meta={"limit": limit})

    while True:
        if usage.steps >= lim.max_steps:
            stop("max_steps", "agent still running after %d steps" % lim.max_steps)
            break
        if lim.max_seconds is not None and clock() - start > lim.max_seconds:
            stop("max_seconds", "run exceeded %.1fs" % lim.max_seconds)
            break
        try:
            reply = adapter.chat(messages, tools)
        except AdapterError as exc:
            trace.outcome, trace.error = "error", str(exc)
            trace.add("error", now_ms(), content=str(exc))
            break
        usage.steps += 1
        usage.prompt_tokens += reply.prompt_tokens
        usage.completion_tokens += reply.completion_tokens
        usage.total_tokens = usage.prompt_tokens + usage.completion_tokens
        if reply.cost_usd is not None:
            usage.cost_usd = (usage.cost_usd or 0.0) + reply.cost_usd
        elif policy.agent.pricing and (reply.prompt_tokens or reply.completion_tokens):
            p = policy.agent.pricing
            usage.cost_usd = (usage.cost_usd or 0.0) + (
                reply.prompt_tokens / 1000 * p.input_per_1k
                + reply.completion_tokens / 1000 * p.output_per_1k)

        trace.add("assistant_message", now_ms(), content=reply.content or "")
        # Calls the agent executed itself and reported: record them as observed.
        for ev in reply.executed:
            usage.tool_calls += 1
            trace.add("tool_call", now_ms(), tool_name=ev["name"], arguments=ev.get("arguments") or {},
                      meta={"executed_by_agent": True})
            if ev.get("result") is not None:
                trace.add("tool_result", now_ms(), tool_name=ev["name"], content=str(ev["result"]),
                          meta={"executed_by_agent": True})

        if not reply.tool_calls:
            break

        messages.append({
            "role": "assistant", "content": reply.content,
            "tool_calls": [{"id": tc.id, "type": "function",
                            "function": {"name": tc.name, "arguments": json.dumps(tc.arguments)}}
                           for tc in reply.tool_calls],
        })
        over_budget = False
        for tc in reply.tool_calls:
            usage.tool_calls += 1
            over = usage.tool_calls > lim.max_tool_calls
            trace.add("tool_call", now_ms(), tool_name=tc.name, tool_call_id=tc.id,
                      arguments=tc.arguments, meta={"over_budget": True} if over else {})
            if over:
                stop("max_tool_calls", "agent requested tool call #%d (budget %d)"
                     % (usage.tool_calls, lim.max_tool_calls))
                over_budget = True
                break
            if scenario.responder and _is_scenario_tool(policy, tc.name):
                result = scenario.responder(tc.name, tc.arguments, scenario_calls)
                scenario_calls += 1
            elif _is_scenario_tool(policy, tc.name):
                result = BENIGN_DOC
            else:
                result = SANDBOX_OK
            trace.add("tool_result", now_ms(), tool_name=tc.name, tool_call_id=tc.id, content=result)
            messages.append({"role": "tool", "tool_call_id": tc.id, "content": result})
        if over_budget:
            break

    trace.duration_s = clock() - start
    return trace


def run_suite(policy: Policy, adapter: AgentAdapter, seed: int = 0,
              only: Optional[List[str]] = None,
              progress: Optional[Callable[[Scenario], None]] = None) -> SuiteResult:
    scenarios, warnings = build_scenarios(ScenarioContext(policy, seed), only=only)
    results: List[ScenarioResult] = []
    for sc in scenarios:
        if progress:
            progress(sc)
        trace = run_scenario(sc, policy, adapter)
        findings = evaluate_trace(sc, trace, policy) if trace.outcome != "error" else []
        results.append(ScenarioResult(sc, trace, findings))
    return SuiteResult(policy, seed, results, warnings)
