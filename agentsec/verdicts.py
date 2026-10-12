"""Verdicts, evaluation metrics and attack timelines computed from a report.json.

One place for the rules every consumer of a report must agree on -- `agentsec compare`, the local
`agentsec dashboard` and the hosted dashboard:

- a scenario is *tested* only when the agent was attacked and judged (status ``passed`` or
  ``findings``). ``inconclusive`` (the adversarial content never reached the agent), ``error`` and
  ``not_observable`` scenarios measured nothing: never a pass, and a finding in a scenario that is
  one of these in the newer run is never "fixed";
- an attack timeline is read from the report, never guessed: the scenario's ``delivery`` record
  (AgentSec after 0.8.0) or, for older reports, the evidence of its ``attack_goal_achieved`` finding.

Everything here works on the plain JSON dicts, so it accepts reports from every AgentSec version:
older reports simply have no inconclusive scenarios, no ``delivery`` and no ``attack_goals``.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from .evaluators import SEVERITIES, severity_rank

STATUSES = ("findings", "error", "inconclusive", "not_observable", "passed")
TESTED = ("findings", "passed")
ATTACK_GOAL_RULE = "attack_goal_achieved"
_GOAL_PREFIX = "Attack succeeded: "


def _scenarios(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [s for s in report.get("scenarios") or [] if isinstance(s, dict)]


def status_of(scenario: Optional[Dict[str, Any]]) -> Optional[str]:
    """A scenario's verdict; None when the scenario is not in the report."""
    if scenario is None:
        return None
    return scenario.get("status") or "passed"


def inconclusive_count(report: Dict[str, Any]) -> int:
    """`summary.inconclusive` (AgentSec 0.8.0+), or the scenarios with that status; 0 for older reports."""
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    value = summary.get("inconclusive")
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return sum(status_of(s) == "inconclusive" for s in _scenarios(report))


def evaluation(report: Dict[str, Any]) -> Dict[str, Any]:
    """What the run measured. Rates are over tested scenarios only; None when nothing was tested."""
    counts = {k: 0 for k in STATUSES}
    scenarios = _scenarios(report)
    for s in scenarios:
        st = status_of(s)
        counts[st] = counts.get(st, 0) + 1
    tested = counts["findings"] + counts["passed"]
    return {
        "scenarios": len(scenarios), "tested": tested, "with_findings": counts["findings"],
        "passed": counts["passed"], "inconclusive": counts["inconclusive"], "errors": counts["error"],
        "not_observable": counts["not_observable"],
        "finding_rate": round(counts["findings"] / tested, 4) if tested else None,
        "coverage": round(tested / len(scenarios), 4) if scenarios else None,
    }


def _events(items: Any) -> List[Dict[str, Any]]:
    return [e for e in items or [] if isinstance(e, dict) and isinstance(e.get("seq"), int) and e.get("type")]


def attack_goals(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    """One timeline per `attack_goal_achieved` finding: the tool result that delivered the payload and the
    later tool call that achieved the attacker's goal. `delivered_*` is None when the scenario does not
    track delivery; positions are None when the report was uploaded without traces."""
    by_id = {s.get("id"): s for s in _scenarios(report)}
    out = []
    for f in report.get("findings") or []:
        if not isinstance(f, dict) or f.get("rule") != ATTACK_GOAL_RULE:
            continue
        scenario = by_id.get(f.get("scenario_id")) or {}
        ev = _events(f.get("evidence"))
        calls = [e for e in ev if e["type"] == "tool_call"]
        action = max(calls, key=lambda e: e["seq"]) if calls else None
        delivered_seq, delivered_tool = None, None
        delivery = scenario.get("delivery") if isinstance(scenario.get("delivery"), dict) else None
        if delivery and isinstance(delivery.get("seq"), int):
            delivered_seq, delivered_tool = delivery["seq"], delivery.get("tool")
        else:
            results = [e for e in ev if e["type"] == "tool_result" and (action is None or e["seq"] < action["seq"])]
            if results:
                last = max(results, key=lambda e: e["seq"])
                delivered_seq, delivered_tool = last["seq"], last.get("tool_name")
        trace_events = _events((scenario.get("trace") or {}).get("events"))
        all_results = [e["seq"] for e in trace_events if e["type"] == "tool_result"]
        position = all_results.index(delivered_seq) + 1 if delivered_seq in all_results else None
        between = None
        if delivered_seq is not None and action and trace_events:
            between = sum(1 for e in trace_events
                          if e["type"] == "tool_call" and delivered_seq < e["seq"] < action["seq"])
        title = f.get("title") or ""
        out.append({
            "finding_id": f.get("id"), "scenario_id": f.get("scenario_id"), "category": f.get("category"),
            "severity": f.get("severity", "low"),
            "goal": title[len(_GOAL_PREFIX):] if title.startswith(_GOAL_PREFIX) else title,
            "delivered_seq": delivered_seq, "delivered_tool": delivered_tool,
            "delivered_in_result": position, "tool_results": len(all_results) if trace_events else None,
            "action_seq": action["seq"] if action else None, "action_tool": action.get("tool_name") if action else None,
            "calls_in_between": between,
        })
    out.sort(key=lambda g: (-severity_rank(g["severity"]) if g["severity"] in SEVERITIES else 0, g["finding_id"] or ""))
    return out


def not_comparable_reason(finding: Dict[str, Any], head: Dict[str, Any]) -> str:
    """Why a baseline finding cannot be called fixed: its scenario is `missing`, or its status in the newer run."""
    for s in _scenarios(head):
        if s.get("id") == finding.get("scenario_id"):
            return status_of(s)
    return "missing"


def verdict_changes(base: Dict[str, Any], head: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Every scenario whose verdict differs between the two runs, baseline order first.
    `base`/`head` is None for a scenario that is only in the other run."""
    b_sc = {s.get("id"): s for s in _scenarios(base)}
    h_sc = {s.get("id"): s for s in _scenarios(head)}
    out = []
    for sid in list(b_sc) + [k for k in h_sc if k not in b_sc]:
        b, h = b_sc.get(sid), h_sc.get(sid)
        if status_of(b) != status_of(h):
            s = h or b
            out.append({"id": sid, "title": s.get("title"), "category": s.get("category"),
                        "base": status_of(b), "head": status_of(h)})
    return out


def agent_reported(report: Dict[str, Any]) -> List[Dict[str, str]]:
    """What the agent said about itself (`x_agentsec.agent`): name, version, backend, model, configuration.
    Empty when the agent reported nothing -- then the report does not say which model, or whether a
    scripted stand-in, made the agent's decisions."""
    value = (report.get("run_config") or {}).get("agent_reported")
    return [d for d in value if isinstance(d, dict)] if isinstance(value, list) else []


def describe_agent(info: Dict[str, str]) -> str:
    """'name 1.2, backend anthropic, model claude-sonnet-4-5, configuration hardened'."""
    head = " ".join(x for x in (info.get("name"), info.get("version")) if x)
    parts = [head] if head else []
    parts += ["%s %s" % (k, info[k]) for k in ("backend", "model", "configuration") if info.get(k)]
    return ", ".join(parts)


__all__ = ["ATTACK_GOAL_RULE", "STATUSES", "TESTED", "agent_reported", "attack_goals", "describe_agent", "evaluation",
           "inconclusive_count", "not_comparable_reason", "status_of", "verdict_changes"]
