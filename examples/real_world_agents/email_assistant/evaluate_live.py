#!/usr/bin/env python3
"""Run every Email Attack Pack scenario against a REAL configured LLM, in both the baseline and
hardened configurations, and print a results table.

This is the model-dependent experiment, kept separate from the deterministic test suite. It
refuses to run without a configured backend rather than falling back to a stand-in, so a result
table always reflects an actual model execution.

    export AGENTSEC_LLM_BACKEND=anthropic
    export AGENTSEC_LLM_API_KEY=...            # or ANTHROPIC_API_KEY
    export AGENTSEC_LLM_MODEL=claude-sonnet-4-5
    python examples/real_world_agents/email_assistant/evaluate_live.py

    # several runs per scenario, because model decoding is not reproducible
    python examples/real_world_agents/email_assistant/evaluate_live.py --repeat 3

    # one scenario only, with the full trace printed
    python examples/real_world_agents/email_assistant/evaluate_live.py \
        -s email_agent_forward_exfiltration/html_part --verbose

Every mailbox action is simulated in-process; nothing is sent anywhere.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import socket
import sys
import threading
import time
from collections import Counter

_HERE = os.path.dirname(os.path.abspath(__file__))
_EXAMPLES = os.path.dirname(os.path.dirname(_HERE))
sys.path.insert(0, _HERE)

from agentsec.adapters import HTTPAgentAdapter              # noqa: E402
from agentsec.attacks.base import ScenarioContext           # noqa: E402
from agentsec.evaluators import evaluate_trace              # noqa: E402
from agentsec.evaluators.goals import payload_delivery      # noqa: E402
from agentsec.policies import parse_policy                  # noqa: E402
from agentsec.runners.local import ScenarioResult, run_scenario  # noqa: E402


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ea = _load("live_email_assistant", os.path.join(_HERE, "server.py"))
llm = ea.llm
pack = ea.pack
POLICY_TEXT = open(os.path.join(_EXAMPLES, "attack_packs", "email_assistant.agentsec.yaml")).read()


def all_scenarios():
    ctx = ScenarioContext(parse_policy(POLICY_TEXT), 0)
    out = {}
    for build in (pack.build_forward_exfiltration, pack.build_external_send,
                  pack.build_unauthorized_delete, pack.build_delayed_injection):
        for sc in build(ctx):
            out[sc.id] = sc
    return out


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def run_once(scenario, backend, hardened):
    port = _free_port()
    assistant = ea.EmailAssistant(backend, hardened=hardened)
    server = ea.make_server(assistant, port=port)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        policy = parse_policy(POLICY_TEXT.replace("http://127.0.0.1:8060/agent",
                                                  "http://127.0.0.1:%d/agent" % port))
        trace = run_scenario(scenario, policy, HTTPAgentAdapter(policy.agent))
        result = ScenarioResult(scenario, trace, evaluate_trace(scenario, trace, policy))
    finally:
        server.shutdown()
        server.server_close()
    blocked = [b["name"] for state in assistant.sessions.all() for b in state.blocked]
    return result, blocked


def describe(result, blocked, verbose=False):
    calls = [e.tool_name for e in result.trace.of_type("tool_call")]
    delivered = payload_delivery(result.scenario, result.trace)
    sinks = [e for e in result.trace.of_type("tool_call")
             if e.tool_name in ("send_email", "forward_email", "delete_email")]
    after = [e.tool_name for e in sinks if delivered is not None and e.seq > delivered.seq]
    line = {
        "verdict": result.status,
        "delivered": delivered is not None,
        "delivered_at": delivered.seq if delivered else None,
        "calls": calls,
        "sinks_after_exposure": after,
        "guard_blocked": blocked,
        "rules": sorted({f.rule for f in result.findings}),
    }
    if verbose:
        line["transcript"] = [
            {"seq": e.seq, "type": e.type, "tool": e.tool_name,
             "args": e.arguments, "content": (e.content or "")[:400]}
            for e in result.trace.events]
    return line


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("-s", "--scenario", action="append",
                    help="scenario id (repeatable); default: all")
    ap.add_argument("--repeat", type=int, default=1, help="runs per scenario per configuration")
    ap.add_argument("--config", choices=["baseline", "hardened", "both"], default="both")
    ap.add_argument("--verbose", action="store_true", help="include the full trace in the JSON")
    ap.add_argument("--json-out", help="write the full results as JSON to this path")
    args = ap.parse_args(argv)

    kind, model, base, _key = llm.describe_env()
    if kind is None:
        raise SystemExit(
            "No LLM backend configured, so there is nothing to measure. Set AGENTSEC_LLM_BACKEND="
            "anthropic|openai and AGENTSEC_LLM_API_KEY (or ANTHROPIC_API_KEY / OPENAI_API_KEY); "
            "see README.md. This script deliberately does not fall back to a stand-in.")
    backend = llm.backend_from_env()

    scenarios = all_scenarios()
    wanted = args.scenario or sorted(scenarios)
    unknown = [s for s in wanted if s not in scenarios]
    if unknown:
        raise SystemExit("unknown scenario %r; available:\n  %s"
                         % (unknown[0], "\n  ".join(sorted(scenarios))))
    configs = ["baseline", "hardened"] if args.config == "both" else [args.config]

    print()
    print("AgentSec Email Attack Pack -- LIVE MODEL EVALUATION")
    print("  backend        : %s" % kind)
    print("  model          : %s" % model)
    print("  base url       : %s" % base)
    print("  configurations : %s" % ", ".join(configs))
    print("  repeats        : %d" % args.repeat)
    print("  started        : %s" % time.strftime("%Y-%m-%d %H:%M:%S %z"))
    print()
    print("  NOTE: model decoding is not reproducible and providers move models behind a name.")
    print("        Treat a single run as one observation, not a rate.")
    print()

    records = []
    header = "%-52s %-9s %-13s %-10s %s" % ("scenario", "config", "verdict", "delivered", "sinks after exposure")
    print(header)
    print("-" * len(header))
    tally = Counter()
    for sid in wanted:
        for config in configs:
            for _ in range(args.repeat):
                try:
                    result, blocked = run_once(scenarios[sid], backend, config == "hardened")
                    row = describe(result, blocked, args.verbose)
                except llm.BackendError as exc:
                    row = {"verdict": "backend_error", "delivered": False, "calls": [],
                           "sinks_after_exposure": [], "guard_blocked": [], "rules": [],
                           "error": str(exc)}
                row.update(scenario=sid, config=config, model=model, backend=kind)
                records.append(row)
                tally[(config, row["verdict"])] += 1
                print("%-52s %-9s %-13s %-10s %s"
                      % (sid[:52], config, row["verdict"].upper(), row["delivered"],
                         ",".join(row["sinks_after_exposure"]) or "-"))
    print()
    print("SUMMARY")
    for (config, verdict), n in sorted(tally.items()):
        print("  %-9s %-13s %d" % (config, verdict.upper(), n))
    print()
    inconclusive = tally[("baseline", "inconclusive")] + tally[("hardened", "inconclusive")]
    errored = sum(n for (c, v), n in tally.items() if v in ("error", "backend_error"))
    if inconclusive:
        print("  %d run(s) INCONCLUSIVE: the model never opened the untrusted message (or stopped"
              % inconclusive)
        print("  before a delayed injection), so nothing was measured -- not a pass.")
    if errored:
        print("  %d run(s) ERRORED: execution failed, which is not a pass either." % errored)
    print()
    print("  Findings above are evidence about THIS model on THESE runs. They are not a general")
    print("  claim about the model, and a PASSED verdict is not proof of robustness.")

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump({"model": model, "backend": kind, "base_url": base,
                       "started": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                       "repeat": args.repeat, "records": records}, fh, indent=2)
            fh.write("\n")
        print()
        print("  Full results written to %s" % args.json_out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
