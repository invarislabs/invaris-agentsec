"""Re-score recorded Claude Code traces with the current evaluators (no agent is called).

Every run of claude_code_mcp.py stores each scenario's full trace. This script rebuilds the
scenarios from the same policy and seed, re-runs AgentSec's deterministic evaluators on those
recorded traces, and merges several partial runs into results/claude_code_final.json. Use it after
changing an evaluator to see the effect on real-agent behavior without spending another run.

    python benchmarks/real-agents/reevaluate.py results/claude_code.json results/claude_code_resume.json
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

from agentsec.attacks import build_scenarios  # noqa: E402
from agentsec.attacks.base import ScenarioContext  # noqa: E402
from agentsec.evaluators import evaluate_trace  # noqa: E402
from agentsec.policies import load_policy  # noqa: E402
from agentsec.traces import Trace  # noqa: E402


def main(paths):
    policy = load_policy(os.path.join(HERE, "policy.yaml"))
    scenarios = {s.id: s for s in build_scenarios(ScenarioContext(policy, 0))[0]}
    final, sources = {}, []
    for path in paths:
        d = json.load(open(path))
        sources.append({"file": os.path.basename(path), "version": d.get("version"),
                        "models_reported": d.get("models_reported"), "total_cost_usd": d.get("total_cost_usd")})
        for sid, v in d["scenarios"].items():
            if v.get("status") == "error" or "trace" not in v:
                final.setdefault(sid, {"status": "not run", "error": v.get("error")})
                continue
            trace = Trace.from_dict(v["trace"])
            findings = evaluate_trace(scenarios[sid], trace, policy)
            final[sid] = {"source": os.path.basename(path), "status": "findings" if findings else "passed",
                          "rules_at_run_time": v["rules"], "rules_now": sorted({f.rule for f in findings}),
                          "findings_now": [{"rule": f.rule, "severity": f.severity, "title": f.title} for f in findings],
                          "calls": [[e.tool_name, e.arguments] for e in trace.of_type("tool_call")],
                          "answers": [e.content[:400] for e in trace.of_type("assistant_message")]}
    out = {"agent": "Claude Code CLI over AgentSec's MCP attack host", "sources": sources,
           "scenarios": dict(sorted(final.items()))}
    with open(os.path.join(HERE, "results", "claude_code_final.json"), "w") as fh:
        json.dump(out, fh, indent=1, sort_keys=True)
        fh.write("\n")
    for sid, v in out["scenarios"].items():
        print("%-62s %-9s now=%s at_run=%s calls=%s" % (sid, v["status"], v.get("rules_now"), v.get("rules_at_run_time"),
                                                       [c[0] for c in v.get("calls", [])]))


if __name__ == "__main__":
    main(sys.argv[1:])
