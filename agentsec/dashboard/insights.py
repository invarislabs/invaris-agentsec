"""Aggregates computed from a report for the dashboard.

Everything here is derived from fields `agentsec test` and `agentsec mcp scan` already write; nothing
is estimated. Where a value is unknown in the report (for example cost without pricing), it stays
unknown (None) rather than becoming zero.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..compare import compare
from ..evaluators import SEVERITIES, severity_rank
from ..owasp import ASI

STATUSES = ("findings", "error", "not_observable", "passed")


def _worst(severities: List[str]) -> Optional[str]:
    known = [s for s in severities if s in SEVERITIES]
    return max(known, key=severity_rank) if known else None


def _severity_by_finding(report: Dict[str, Any]) -> Dict[str, str]:
    return {f["id"]: f.get("severity", "low") for f in report.get("findings", [])}


def _owasp(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    counts: Dict[str, int] = {}
    worst: Dict[str, List[str]] = {}
    for f in report.get("findings", []):
        for ref in f.get("owasp", []):
            counts[ref["id"]] = counts.get(ref["id"], 0) + 1
            worst.setdefault(ref["id"], []).append(f.get("severity", "low"))
    names = dict(ASI)
    names.update((report.get("owasp_framework") or {}).get("categories") or {})
    return [{"id": k, "name": names[k], "findings": counts.get(k, 0), "worst": _worst(worst.get(k, []))}
            for k in sorted(names)]


def _rules(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    rules: Dict[str, Dict[str, Any]] = {}
    for f in report.get("findings", []):
        r = rules.setdefault(f["rule"], {"rule": f["rule"], "findings": 0, "severities": [], "scenarios": set(),
                                          "source": f.get("source", "deterministic")})
        r["findings"] += 1
        r["severities"].append(f.get("severity", "low"))
        r["scenarios"].add(f.get("scenario_id"))
    out = []
    for r in rules.values():
        out.append({"rule": r["rule"], "findings": r["findings"], "scenarios": len(r["scenarios"]),
                    "worst": _worst(r["severities"]), "source": r["source"]})
    return sorted(out, key=lambda r: (-severity_rank(r["worst"]), -r["findings"], r["rule"]))


def suite_insights(report: Dict[str, Any]) -> Dict[str, Any]:
    sev_of = _severity_by_finding(report)
    policy = (report.get("run_config") or {}).get("policy") or {}
    allowed = set(policy.get("allowed_tools") or [])
    forbidden = set(policy.get("forbidden_actions") or [])

    categories: Dict[str, Dict[str, Any]] = {}
    vectors: Dict[str, Dict[str, int]] = {}
    tools: Dict[str, Dict[str, Any]] = {}
    outcomes: Dict[str, int] = {}
    limits: Dict[str, int] = {}
    errors: Dict[str, int] = {}
    actors: Dict[str, int] = {}
    usage = {"steps": 0, "tool_calls": 0, "prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0,
             "duration_s": 0.0}
    cost_values: List[float] = []
    cost_unknown = 0
    multi_session = 0

    for s in report.get("scenarios", []):
        status = s.get("status", "passed")
        worst = _worst([sev_of.get(fid, "low") for fid in s.get("finding_ids", [])])
        cat = categories.setdefault(s.get("category", "other"), {
            "category": s.get("category", "other"), "scenarios": 0, "findings": 0,
            "by_status": {k: 0 for k in STATUSES}, "severities": [], "cells": []})
        cat["scenarios"] += 1
        cat["findings"] += len(s.get("finding_ids", []))
        cat["by_status"][status] = cat["by_status"].get(status, 0) + 1
        if worst:
            cat["severities"].append(worst)
        cat["cells"].append({"id": s["id"], "title": s.get("title"), "status": status, "worst": worst,
                             "findings": len(s.get("finding_ids", [])), "vector": s.get("vector")})

        v = vectors.setdefault(s.get("vector") or "unknown", {"vector": s.get("vector") or "unknown",
                                                               "scenarios": 0, "with_findings": 0, "errors": 0})
        v["scenarios"] += 1
        v["with_findings"] += status == "findings"
        v["errors"] += status == "error"

        trace = s.get("trace") or {}
        outcomes[trace.get("outcome", "completed")] = outcomes.get(trace.get("outcome", "completed"), 0) + 1
        if trace.get("limit"):
            limits[trace["limit"]] = limits.get(trace["limit"], 0) + 1
        if trace.get("error"):
            errors[trace["error"]] = errors.get(trace["error"], 0) + 1
        u = trace.get("usage") or {}
        for k in ("steps", "tool_calls", "prompt_tokens", "completion_tokens", "total_tokens"):
            usage[k] += int(u.get(k) or 0)
        usage["duration_s"] += float(trace.get("duration_s") or 0.0)
        if u.get("cost_usd") is None:
            cost_unknown += 1
        else:
            cost_values.append(float(u["cost_usd"]))
        phases = set()
        for e in trace.get("events", []):
            meta = e.get("meta") or {}
            if "phase" in meta:
                phases.add(meta["phase"])
            if meta.get("actor"):
                actors[meta["actor"]] = actors.get(meta["actor"], 0) + 1
            if e.get("type") == "tool_call" and e.get("tool_name"):
                name = e["tool_name"]
                t = tools.setdefault(name, {"tool": name, "calls": 0, "scenarios": set(),
                                            "allowed": name in allowed, "forbidden": name in forbidden})
                t["calls"] += 1
                t["scenarios"].add(s["id"])
        if len(phases) > 1:
            multi_session += 1

    cats = []
    for c in categories.values():
        c["worst"] = _worst(c.pop("severities"))
        cats.append(c)
    tool_list = [{"tool": t["tool"], "calls": t["calls"], "scenarios": len(t["scenarios"]),
                  "allowed": t["allowed"], "forbidden": t["forbidden"]} for t in tools.values()]
    tool_list.sort(key=lambda t: (not t["forbidden"], t["allowed"], -t["calls"], t["tool"]))
    usage["duration_s"] = round(usage["duration_s"], 3)
    usage["cost_usd"] = round(sum(cost_values), 6) if cost_values and not cost_unknown else None
    usage["cost_known_scenarios"] = len(cost_values)
    usage["cost_unknown_scenarios"] = cost_unknown

    return {
        "kind": "test",
        "categories": cats,
        "vectors": sorted(vectors.values(), key=lambda v: v["vector"]),
        "owasp": _owasp(report),
        "rules": _rules(report),
        "tools": tool_list,
        "outcomes": outcomes,
        "limits": limits,
        "errors": [{"message": m, "scenarios": n} for m, n in sorted(errors.items(), key=lambda x: -x[1])],
        "actors": [{"actor": a, "events": n} for a, n in sorted(actors.items(), key=lambda x: -x[1])],
        "multi_session_scenarios": multi_session,
        "usage": usage,
        "model_assisted": sum(f.get("source") == "model-assisted" for f in report.get("findings", [])),
    }


def mcp_insights(report: Dict[str, Any]) -> Dict[str, Any]:
    sev_of = _severity_by_finding(report)
    described: Dict[str, Dict[str, Any]] = {}
    for t in report.get("tools", []):
        described["mcp/%s" % t.get("name")] = {"kind": "tool", "description": t.get("description")}
    for r in report.get("resources", []):
        described["mcp/resource:%s" % r.get("uri")] = {"kind": "resource", "description": r.get("description"),
                                                         "name": r.get("name")}
    for p in report.get("prompts", []):
        described["mcp/prompt:%s" % p.get("name")] = {"kind": "prompt", "description": p.get("description")}
    items = []
    for s in report.get("scenarios", []):
        d = described.get(s["id"], {"kind": "removed", "description": None})
        items.append({"id": s["id"], "title": s.get("title"), "status": s.get("status", "passed"),
                      "kind": d["kind"], "description": d.get("description"), "name": d.get("name"),
                      "findings": len(s.get("finding_ids", [])),
                      "worst": _worst([sev_of.get(fid, "low") for fid in s.get("finding_ids", [])])})
    return {"kind": "mcp_scan", "items": items, "owasp": _owasp(report), "rules": _rules(report)}


def insights(report: Dict[str, Any]) -> Dict[str, Any]:
    return mcp_insights(report) if report.get("kind") == "mcp_scan" else suite_insights(report)


def compare_reports(base: Dict[str, Any], head: Dict[str, Any]) -> Dict[str, Any]:
    """`agentsec compare`, as data. Severity changes carry the baseline severity too."""
    c = compare(base, head)
    base_sev = _severity_by_finding(base)

    def slim(f: Dict[str, Any]) -> Dict[str, Any]:
        d = {k: f.get(k) for k in ("id", "rule", "scenario_id", "category", "severity", "title", "source")}
        if f["id"] in base_sev and base_sev[f["id"]] != f.get("severity"):
            d["previous_severity"] = base_sev[f["id"]]
        return d

    def order(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [slim(f) for f in sorted(items, key=lambda x: (-severity_rank(x["severity"]), x["id"]))]

    return {
        "new": order(c.new), "worse": order(c.worse), "fixed": order(c.fixed), "better": order(c.better),
        "unchanged": order(c.unchanged), "not_comparable": order(c.not_comparable),
        "warnings": c.warnings,
        "regressions": len(c.regressions("low")),
    }
