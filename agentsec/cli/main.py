from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional

from .. import __version__
from ..adapters import HTTPAgentAdapter
from ..compare import CompareError, compare, load as load_compare_report, render as render_compare
from ..evaluators import SEVERITIES, severity_rank
from ..mcp import (MCPError, build_mcp_report, compare_pins, connect_http, connect_stdio, make_pins,
                   render_mcp_terminal, scan_tools)
from ..mcp.report import write_mcp_report
from ..policies import PolicyError, load_policy, policy_json_schema
from ..reports import (FORMATS, annotations, append_step_summary, in_github_actions,
                       render_markdown, render_terminal, write_reports)
from ..runners import load_report, replay, run_suite
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


def _parse_formats(text: str) -> List[str]:
    formats = [f.strip() for f in text.split(",") if f.strip()]
    bad = [f for f in formats if f not in FORMATS]
    if bad or not formats:
        raise PolicyError("--format must be a comma-separated list of: %s" % ", ".join(FORMATS))
    return formats


def _cmd_test(args: argparse.Namespace) -> int:
    policy = load_policy(args.policy)
    adapter = HTTPAgentAdapter(policy.agent)
    only = args.scenario or None
    progress = None
    if args.verbose:
        progress = lambda sc: print("running %s" % sc.id, file=sys.stderr)
    formats = _parse_formats(args.format)
    suite = run_suite(policy, adapter, seed=args.seed, only=only, progress=progress, judge=args.judge)
    report, paths = write_reports(suite, args.out, formats)
    print(render_terminal(suite, report_path=paths, color=sys.stdout.isatty(), verbose=args.verbose))
    if in_github_actions():
        for line in annotations(report):
            print(line)
        append_step_summary(render_markdown(report))

    if suite.results and all(r.status == "error" for r in suite.results):
        print("\nEvery scenario errored; is the agent running at %s?" % policy.agent.endpoint,
              file=sys.stderr)
        return EXIT_ERROR
    if args.fail_on != "none":
        threshold = severity_rank(args.fail_on)
        if any(severity_rank(f.severity) >= threshold for f in suite.findings):
            return EXIT_FINDINGS
    return EXIT_OK


def _cmd_replay(args: argparse.Namespace) -> int:
    report = load_report(args.report)
    policy = load_policy(args.policy)
    result = replay(report, policy, HTTPAgentAdapter(policy.agent),
                    finding_ids=args.finding or None, scenario_ids=args.scenario or None,
                    judge=args.judge)
    if result.skipped_model_assisted:
        print("note: skipped %d model-assisted finding(s); pass --judge to re-check them"
              % result.skipped_model_assisted)
    if not result.outcomes:
        print("Nothing to replay: the report has no matching findings.")
        return EXIT_OK
    print("Replaying %d finding%s from %s (seed %d)" % (
        len(result.outcomes), "" if len(result.outcomes) == 1 else "s", args.report, result.seed))
    if result.policy_changed:
        print("note: the policy file differs from the one used for the report")
    label = {"reproduced": "REPRODUCED", "not_reproduced": "NOT REPRODUCED", "error": "ERROR"}
    for o in result.outcomes:
        print("%-15s %-8s %s  [%s]" % (label[o.status], o.severity, o.title, o.scenario_id))
    for f in result.new_findings:
        print("%-15s %-8s %s  [%s]" % ("NEW", f.severity, f.title, f.scenario_id))
    print("\n%d reproduced, %d not reproduced, %d new, %d errored" % (
        len(result.reproduced), sum(o.status == "not_reproduced" for o in result.outcomes),
        len(result.new_findings), len(result.errors)))
    if result.suite is not None:
        _, paths = write_reports(result.suite, args.out, ["json"])
        print("Report written to %s" % paths[0])
    if result.errors:
        return EXIT_ERROR
    return EXIT_FINDINGS if (result.reproduced or result.new_findings) else EXIT_OK


def _cmd_compare(args: argparse.Namespace) -> int:
    try:
        result = compare(load_compare_report(args.baseline), load_compare_report(args.current))
    except CompareError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return EXIT_ERROR
    print(render_compare(result))
    if args.fail_on == "none":
        return EXIT_OK
    return EXIT_FINDINGS if result.regressions(args.fail_on) else EXIT_OK


def _cmd_mcp_scan(args: argparse.Namespace) -> int:
    allowed, forbidden = None, None
    if args.policy:
        policy = load_policy(args.policy)
        allowed, forbidden = policy.allowed_tools, policy.forbidden_actions
    headers = {}
    for h in args.header or []:
        if "=" not in h:
            raise PolicyError("--header must look like Name=value")
        k, v = h.split("=", 1)
        headers[k.strip()] = os.path.expandvars(v)
    try:
        client = (connect_stdio(args.command, args.timeout) if args.command
                  else connect_http(args.url, headers, args.timeout))
        with client:
            client.initialize()
            tools = client.list_tools()
            second = client.list_tools() if args.recheck else None
            info = client.server_info
    except MCPError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return EXIT_ERROR
    findings = scan_tools(tools, allowed, forbidden)
    if second is not None:
        findings += compare_pins(make_pins(tools), second)
    if args.pin_write:
        with open(args.pin_write, "w", encoding="utf-8") as fh:
            json.dump(make_pins(tools), fh, indent=2)
            fh.write("\n")
        print("Pinned %d tool definition(s) to %s" % (len(tools), args.pin_write))
    elif args.pin:
        try:
            with open(args.pin, encoding="utf-8") as fh:
                pins = json.load(fh)
        except (OSError, ValueError) as exc:
            print("error: cannot read pin file %s: %s" % (args.pin, exc), file=sys.stderr)
            return EXIT_ERROR
        findings += compare_pins(pins, tools)
    report = build_mcp_report(args.command or args.url, info, tools, findings)
    path = write_mcp_report(report, args.out)
    print(render_mcp_terminal(report))
    print("\nReport written to %s" % path)
    if in_github_actions():
        for line in annotations(report):
            print(line)
    if args.fail_on != "none":
        threshold = severity_rank(args.fail_on)
        if any(severity_rank(f.severity) >= threshold for f in findings):
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
    t.add_argument("--format", "-f", default="json,html",
                   help="report formats, comma-separated: json, html, markdown (default json,html)")
    t.add_argument("--seed", type=int, default=0, help="seed for canaries/markers; same seed = same scenarios")
    t.add_argument("--scenario", "-s", action="append", help="only run this category or scenario id (repeatable)")
    t.add_argument("--fail-on", choices=list(SEVERITIES) + ["none"], default="low",
                   help="exit 1 if a finding at or above this severity exists (default low = any)")
    t.add_argument("--judge", action="store_true",
                   help="also run the model-assisted evaluators configured under `judge:` in the policy")
    t.add_argument("--verbose", "-v", action="store_true")
    t.set_defaults(func=_cmd_test)

    r = sub.add_parser("replay", help="re-run findings from a report to see whether they still reproduce")
    r.add_argument("report", help="report.json from an earlier run")
    r.add_argument("--policy", "-p", default="agentsec.yaml")
    r.add_argument("--out", "-o", default=".agentsec/replay", help="directory for the replay report")
    r.add_argument("--finding", action="append", help="replay only this finding id (repeatable)")
    r.add_argument("--scenario", "-s", action="append", help="replay only findings of this scenario id (repeatable)")
    r.add_argument("--judge", action="store_true", help="enable the judge so model-assisted findings can be re-checked")
    r.set_defaults(func=_cmd_replay)

    c = sub.add_parser("compare", help="diff two report.json files and flag regressions")
    c.add_argument("baseline", help="earlier report.json (for example from main)")
    c.add_argument("current", help="newer report.json (for example from a pull request)")
    c.add_argument("--fail-on", choices=list(SEVERITIES) + ["none"], default="low",
                   help="exit 1 if a new or worsened finding at or above this severity exists (default low)")
    c.set_defaults(func=_cmd_compare)

    m = sub.add_parser("mcp", help="test MCP servers")
    msub = m.add_subparsers(dest="mcp_command", required=True)
    ms = msub.add_parser("scan", help="connect to an MCP server, list its tools and check the definitions "
                                      "(never calls a tool)")
    target = ms.add_mutually_exclusive_group(required=True)
    target.add_argument("--command", help="start a stdio server with this command, e.g. 'python server.py'")
    target.add_argument("--url", help="streamable-HTTP server URL")
    ms.add_argument("--header", action="append", help="HTTP header Name=value (repeatable; $ENV_VARS are expanded)")
    ms.add_argument("--policy", "-p", help="agentsec.yaml whose allowed_tools / forbidden_actions the server is checked against")
    ms.add_argument("--pin", help="pin file from an earlier --pin-write; changed definitions are reported")
    ms.add_argument("--pin-write", help="write a pin file with the current definitions")
    ms.add_argument("--recheck", action="store_true", help="list tools twice in one session and report changes")
    ms.add_argument("--out", "-o", default=".agentsec", help="report directory (default .agentsec)")
    ms.add_argument("--timeout", type=float, default=20.0)
    ms.add_argument("--fail-on", choices=list(SEVERITIES) + ["none"], default="low")
    ms.set_defaults(func=_cmd_mcp_scan)

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
