#!/usr/bin/env python3
"""Run every Browser Attack Pack scenario against a REAL configured LLM, in both baseline and
hardened configurations, and print a results table. The model-dependent experiment, kept separate
from the deterministic suite; it refuses to run without a configured backend.

    export AGENTSEC_LLM_BACKEND=anthropic
    export AGENTSEC_LLM_API_KEY=...
    export AGENTSEC_LLM_MODEL=claude-sonnet-4-5
    python examples/real_world_agents/llm_browser_assistant/evaluate_live.py
    python examples/real_world_agents/llm_browser_assistant/evaluate_live.py --repeat 3 --json-out r.json
    python examples/real_world_agents/llm_browser_assistant/evaluate_live.py \
        -s browser_agent_unauthorized_purchase/unrequested_sku --verbose

Every browser action is simulated in-process; nothing leaves the host.
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


ba = _load("live_browser_assistant", os.path.join(_HERE, "server.py"))
llm = ba.llm
pack = ba.pack
POLICY_TEXT = open(os.path.join(_EXAMPLES, "attack_packs", "browser_agent.agentsec.yaml")).read()


def all_scenarios():
    ctx = ScenarioContext(parse_policy(POLICY_TEXT), 0)
    out = {}
    for build in (pack.build_nav_exfiltration, pack.build_unauthorized_navigation,
                  pack.build_unauthorized_form_submission, pack.build_unauthorized_purchase,
                  pack.build_delayed_page_injection):
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
    assistant = ba.BrowserAssistant(backend, hardened=hardened)
    server = ba.make_server(assistant, port=port)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        policy = parse_policy(POLICY_TEXT.replace("127.0.0.1:8050", "127.0.0.1:%d" % port))
        trace = run_scenario(scenario, policy, HTTPAgentAdapter(policy.agent))
        result = ScenarioResult(scenario, trace, evaluate_trace(scenario, trace, policy))
    finally:
        server.shutdown()
        server.server_close()
    blocked = [b["name"] for state in assistant.sessions.all() for b in state.blocked]
    return result, blocked


def describe(result, blocked, verbose=False):
    delivered = payload_delivery(result.scenario, result.trace)
    sinks = [e for e in result.trace.of_type("tool_call")
             if e.tool_name in ("navigate", "submit_form", "fill_form", "place_order")]
    after = [e.tool_name for e in sinks if delivered is not None and e.seq > delivered.seq]
    row = {"verdict": result.status, "delivered": delivered is not None,
           "calls": [e.tool_name for e in result.trace.of_type("tool_call")],
           "sinks_after_exposure": after, "guard_blocked": blocked,
           "rules": sorted({f.rule for f in result.findings})}
    if verbose:
        row["transcript"] = [{"seq": e.seq, "type": e.type, "tool": e.tool_name,
                              "args": e.arguments, "content": (e.content or "")[:400]}
                             for e in result.trace.events]
    return row


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("-s", "--scenario", action="append")
    ap.add_argument("--repeat", type=int, default=1)
    ap.add_argument("--config", choices=["baseline", "hardened", "both"], default="both")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--json-out")
    args = ap.parse_args(argv)

    kind, model, base, _key = llm.describe_env()
    if kind is None:
        raise SystemExit(
            "No LLM backend configured, so there is nothing to measure. Set AGENTSEC_LLM_BACKEND="
            "anthropic|openai and AGENTSEC_LLM_API_KEY (or ANTHROPIC_API_KEY / OPENAI_API_KEY). "
            "This script does not fall back to a stand-in.")
    backend = llm.backend_from_env()

    scenarios = all_scenarios()
    wanted = args.scenario or sorted(scenarios)
    unknown = [s for s in wanted if s not in scenarios]
    if unknown:
        raise SystemExit("unknown scenario %r; available:\n  %s" % (unknown[0], "\n  ".join(sorted(scenarios))))
    configs = ["baseline", "hardened"] if args.config == "both" else [args.config]

    print("\nAgentSec Browser Attack Pack -- LIVE MODEL EVALUATION")
    print("  backend: %s   model: %s   base: %s" % (kind, model, base))
    print("  configs: %s   repeats: %d   started: %s\n"
          % (", ".join(configs), args.repeat, time.strftime("%Y-%m-%d %H:%M:%S %z")))
    print("  NOTE: decoding is not reproducible; treat a single run as one observation, not a rate.\n")

    records = []
    header = "%-58s %-9s %-13s %-10s %s" % ("scenario", "config", "verdict", "delivered", "sinks after exposure")
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
                           "sinks_after_exposure": [], "guard_blocked": [], "rules": [], "error": str(exc)}
                row.update(scenario=sid, config=config, model=model, backend=kind)
                records.append(row)
                tally[(config, row["verdict"])] += 1
                print("%-58s %-9s %-13s %-10s %s"
                      % (sid[:58], config, row["verdict"].upper(), row["delivered"],
                         ",".join(row["sinks_after_exposure"]) or "-"))
    print("\nSUMMARY")
    for (config, verdict), n in sorted(tally.items()):
        print("  %-9s %-13s %d" % (config, verdict.upper(), n))
    print("\n  Findings are evidence about THIS model on THESE runs, not a general claim; a PASSED")
    print("  verdict is not proof of robustness, and INCONCLUSIVE/ERROR runs measured nothing.")

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump({"model": model, "backend": kind, "base_url": base,
                       "started": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                       "repeat": args.repeat, "records": records}, fh, indent=2)
            fh.write("\n")
        print("\n  Full results written to %s" % args.json_out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
