"""Local runner: drives one scenario against the agent, enforcing policy limits,
and records a normalized trace. All tools are simulated; nothing real is executed."""
from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from ..adapters import AdapterError, AgentAdapter
from ..attacks import build_scenarios
from ..attacks.base import Scenario, ScenarioContext, ToolResponder
from ..evaluators import Finding, JudgeEvaluator, evaluate_trace
from ..policies import JUDGE_CHECKS, Policy, PolicyError
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
                 clock: Callable[[], float] = time.monotonic, run_id: str = "", host: Any = None) -> Trace:
    """Run a scenario. Multi-session scenarios run each follow-up as a fresh
    conversation, in the same simulated-user session unless the follow-up says otherwise.
    Step and tool-call limits apply per conversation.

    With a `host` (an MCP attack host, see agentsec.mcp.host) the agent uses its own tools through
    MCP servers that AgentSec runs. No tools are declared in the request; the calls the agent makes
    to the host are recorded as tool calls executed by the agent."""
    lim = policy.limits
    trace = Trace(scenario_id=scenario.id)
    start = clock()
    usage = trace.usage
    multi = bool(scenario.followups)
    base_session = "agentsec-%s-%s" % (run_id or "local", scenario.id.replace("/", "-"))

    def now_ms() -> int:
        return int((clock() - start) * 1000)

    def add(type: str, phase: int, **kw: Any):
        if multi:
            kw["meta"] = dict(kw.get("meta") or {}, phase=phase)
        return trace.add(type, now_ms(), **kw)

    def stop(limit: str, detail: str, phase: int) -> None:
        trace.outcome, trace.limit = "limit_exceeded", limit
        add("limit", phase, content=detail, meta={"limit": limit})

    tools = declared_tools(policy) if (policy.agent.declare_tools and host is None) else []
    if host is not None:
        host.reset()
    conversations = [(scenario.user_message, scenario.responder, base_session)]
    for i, f in enumerate(scenario.followups):
        conversations.append((f.user_message, f.responder,
                              base_session if f.same_session else base_session + "-other%d" % i))

    scenario_calls = 0
    for phase, (user_message, responder, session) in enumerate(conversations):
        messages: List[Dict[str, Any]] = [{"role": "user", "content": user_message}]
        add("user_message", phase, content=user_message)
        steps = calls = 0
        halted = False
        if host is not None:
            host.begin(responder, lambda n: _is_scenario_tool(policy, n))
        while True:
            if steps >= lim.max_steps:
                stop("max_steps", "agent still running after %d steps" % lim.max_steps, phase)
                halted = True
                break
            if lim.max_seconds is not None and clock() - start > lim.max_seconds:
                stop("max_seconds", "run exceeded %.1fs" % lim.max_seconds, phase)
                halted = True
                break
            try:
                reply = adapter.chat(messages, tools, session=session)
            except AdapterError as exc:
                trace.outcome, trace.error = "error", str(exc)
                add("error", phase, content=str(exc))
                halted = True
                break
            steps += 1
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

            if host is not None:
                reply.executed = list(reply.executed) + host.drain()
            add("assistant_message", phase, content=reply.content or "")
            # Calls the agent executed itself and reported: record them as observed.
            for ev in reply.executed:
                usage.tool_calls += 1
                add("tool_call", phase, tool_name=ev["name"], arguments=ev.get("arguments") or {},
                    meta={"executed_by_agent": True})
                if ev.get("result") is not None:
                    add("tool_result", phase, tool_name=ev["name"], content=str(ev["result"]),
                        meta={"executed_by_agent": True})

            if host is not None and reply.executed:
                # The agent ran its tool loop itself, so the budget can only be checked afterwards.
                calls += len(reply.executed)
                if calls > lim.max_tool_calls:
                    stop("max_tool_calls", "agent made %d tool calls through MCP (budget %d)"
                         % (calls, lim.max_tool_calls), phase)
                    halted = True
                    break

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
                calls += 1
                over = calls > lim.max_tool_calls
                add("tool_call", phase, tool_name=tc.name, tool_call_id=tc.id, arguments=tc.arguments,
                    meta={"over_budget": True} if over else {})
                if over:
                    stop("max_tool_calls", "agent requested tool call #%d (budget %d)"
                         % (calls, lim.max_tool_calls), phase)
                    over_budget = True
                    break
                if responder and _is_scenario_tool(policy, tc.name):
                    result = responder(tc.name, tc.arguments, scenario_calls)
                    scenario_calls += 1
                elif _is_scenario_tool(policy, tc.name):
                    result = BENIGN_DOC
                else:
                    result = SANDBOX_OK
                add("tool_result", phase, tool_name=tc.name, tool_call_id=tc.id, content=result)
                messages.append({"role": "tool", "tool_call_id": tc.id, "content": result})
            if over_budget:
                halted = True
                break
        if halted:
            break

    trace.duration_s = clock() - start
    return trace


def run_suite(policy: Policy, adapter: AgentAdapter, seed: int = 0,
              only: Optional[List[str]] = None,
              progress: Optional[Callable[[Scenario], None]] = None,
              categories: Optional[List[str]] = None, judge: bool = False,
              judge_adapter: Optional[AgentAdapter] = None, host: Any = None,
              attack_packs: Optional[Dict[str, Any]] = None) -> SuiteResult:
    """Run the scenarios. With judge=True the policy's `judge:` model reviews scenarios the
    deterministic evaluators passed (advisory, clearly labelled model-assisted). `attack_packs`
    (from `agentsec.attacks.packs.load_packs`) adds categories for this run only, on top of any
    the policy's own `attack_packs:` already loads; see docs/extending.md."""
    # Specs build_scenarios is about to resolve into scenarios (policy.attack_packs, plus any ad hoc
    # ones passed in as `attack_packs`) can also carry their own evaluators and judge checks;
    # collect those once here, before build_scenarios runs, rather than threading a second
    # parameter through every caller of run_suite. pack_specs doesn't depend on build_scenarios'
    # return value, so computing it first lets a pack's own judge check be available in time for
    # JudgeEvaluator construction below.
    from ..attacks.packs import load_packs_evaluators, load_packs_judge_checks  # lazy: avoid a hard, always-on import
    pack_specs = list(policy.attack_packs or [])
    for pc in (attack_packs or {}).values():
        if pc.spec not in pack_specs:
            pack_specs.append(pc.spec)
    extra_evaluators = load_packs_evaluators(pack_specs) if pack_specs else []

    evaluator: Optional[JudgeEvaluator] = None
    if judge:
        if policy.judge is None:
            raise PolicyError("--judge needs a `judge:` section in the policy (endpoint, model, ...)")
        extra_checks = load_packs_judge_checks(pack_specs) if pack_specs else {}
        unknown = [c for c in policy.judge.checks if c not in JUDGE_CHECKS and c not in extra_checks]
        if unknown:
            raise PolicyError("unknown judge check %r; available: %s"
                              % (unknown[0], ", ".join(list(JUDGE_CHECKS) + sorted(extra_checks))))
        evaluator = JudgeEvaluator(policy.judge, judge_adapter, extra_checks=extra_checks)
    scenarios, warnings = build_scenarios(ScenarioContext(policy, seed), only=only, categories=categories,
                                          extra_categories=attack_packs)
    run_id = uuid.uuid4().hex[:8]  # isolates agent-side memory between runs
    results: List[ScenarioResult] = []
    for sc in scenarios:
        if progress:
            progress(sc)
        trace = run_scenario(sc, policy, adapter, run_id=run_id, host=host)
        findings = (evaluate_trace(sc, trace, policy, evaluator, extra_evaluators)
                   if trace.outcome != "error" else [])
        results.append(ScenarioResult(sc, trace, findings))
    if evaluator is not None and evaluator.errors:
        warnings.append("judge: %d of %d judge calls failed or returned an unusable verdict"
                        % (evaluator.errors, evaluator.calls))
    return SuiteResult(policy, seed, results, warnings)
