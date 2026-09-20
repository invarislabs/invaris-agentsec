from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from .. import __version__
from ..adapters import HTTPAgentAdapter
from ..evaluators import SEVERITIES, severity_rank
from ..policies import PolicyError, load_policy, policy_json_schema
from ..reports import render_terminal, write_json_report
from ..runners import run_suite
from ..traces import trace_json_schema

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2

INIT_POLICY = """version: "1"

agent:
  name: my-agent
  endpoint: http://localhost:8000/v1/chat/completions

allowed_tools:
  - search_documents
  - create_draft

forbidden_actions:
  - send_email
  - reveal_credentials
  - execute_payment

# Synthetic credentials your agent can see; they must never appear in its output.
secrets: []

limits:
  max_steps: 12
  max_tool_calls: 10
  max_cost_usd: 0.50

tests:
  - prompt_injection
  - indirect_prompt_injection
  - secret_extraction
  - unauthorized_tool_use
  - tool_output_poisoning
  - unsafe_retrieved_documents
  - loop_and_budget_limits
"""


def _cmd_test(args: argparse.Namespace) -> int:
    policy = load_policy(args.policy)
    adapter = HTTPAgentAdapter(policy.agent)
    only = args.scenario or None
    progress = None
    if args.verbose:
        progress = lambda sc: print("running %s" % sc.id, file=sys.stderr)
    suite = run_suite(policy, adapter, seed=args.seed, only=only, progress=progress)
    path = write_json_report(suite, args.out)
    print(render_terminal(suite, report_path=path, color=sys.stdout.isatty(), verbose=args.verbose))

    if suite.results and all(r.status == "error" for r in suite.results):
        print("\nEvery scenario errored; is the agent running at %s?" % policy.agent.endpoint,
              file=sys.stderr)
        return EXIT_ERROR
    if args.fail_on != "none":
        threshold = severity_rank(args.fail_on)
        if any(severity_rank(f.severity) >= threshold for f in suite.findings):
            return EXIT_FINDINGS
    return EXIT_OK


def _cmd_init(args: argparse.Namespace) -> int:
    try:
        with open(args.path, "x", encoding="utf-8") as fh:
            fh.write(INIT_POLICY)
    except FileExistsError:
        print("error: %s already exists" % args.path, file=sys.stderr)
        return EXIT_ERROR
    print("Wrote %s" % args.path)
    return EXIT_OK


def _cmd_schema(args: argparse.Namespace) -> int:
    schema = policy_json_schema() if args.name == "policy" else trace_json_schema()
    print(json.dumps(schema, indent=2))
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="agentsec", description="Adversarial security testing for AI agents.")
    p.add_argument("--version", action="version", version="agentsec " + __version__)
    sub = p.add_subparsers(dest="command", required=True)

    t = sub.add_parser("test", help="run the adversarial suite against the agent in the policy")
    t.add_argument("--policy", "-p", default="agentsec.yaml")
    t.add_argument("--out", "-o", default=".agentsec", help="report directory (default .agentsec)")
    t.add_argument("--seed", type=int, default=0, help="seed for canaries/markers; same seed = same scenarios")
    t.add_argument("--scenario", "-s", action="append", help="only run this category or scenario id (repeatable)")
    t.add_argument("--fail-on", choices=list(SEVERITIES) + ["none"], default="low",
                   help="exit 1 if a finding at or above this severity exists (default low = any)")
    t.add_argument("--verbose", "-v", action="store_true")
    t.set_defaults(func=_cmd_test)

    i = sub.add_parser("init", help="write a starter agentsec.yaml")
    i.add_argument("path", nargs="?", default="agentsec.yaml")
    i.set_defaults(func=_cmd_init)

    s = sub.add_parser("schema", help="print the JSON schema for policies or traces")
    s.add_argument("name", choices=["policy", "trace"])
    s.set_defaults(func=_cmd_schema)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except PolicyError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
