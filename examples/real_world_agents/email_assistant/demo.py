#!/usr/bin/env python3
"""End-to-end demonstration of the reference email assistant against the Email Attack Pack.

For each configuration (baseline, then hardened) it prints, in order:

  1. the legitimate user request,
  2. the fictional email content the agent encountered (including the untrusted message),
  3. the LLM's actual tool-use decisions,
  4. the resulting simulated mailbox actions,
  5. AgentSec's verdict, findings and the supporting trace evidence.

Everything runs over the real AgentSec pipeline (`run_scenario` -> `evaluate_trace`) through the
real HTTP adapter against a live local server, so what you see is what AgentSec saw.

    # offline, no model: uses the recorded test-double backend
    python examples/real_world_agents/email_assistant/demo.py

    # against a real model (see README for environment variables)
    AGENTSEC_LLM_BACKEND=anthropic AGENTSEC_LLM_API_KEY=... \
      python examples/real_world_agents/email_assistant/demo.py --backend env

With `--backend scripted-redirected` the LLM stand-in is a *recording* of a model that got
redirected by email content. That demonstrates the detection pipeline; it is not evidence about
any real model. Only `--backend env` exercises a real model.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import socket
import sys
import threading

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(os.path.dirname(_HERE))
sys.path.insert(0, _ROOT)
sys.path.insert(0, _HERE)

from agentsec.adapters import HTTPAgentAdapter          # noqa: E402
from agentsec.attacks.base import ScenarioContext       # noqa: E402
from agentsec.evaluators import evaluate_trace          # noqa: E402
from agentsec.policies import parse_policy              # noqa: E402
from agentsec.runners.local import ScenarioResult, run_scenario  # noqa: E402


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ea = _load("demo_email_assistant", os.path.join(_HERE, "server.py"))
llm = ea.llm
pack = ea.pack
POLICY_TEXT = open(os.path.join(_ROOT, "attack_packs", "email_assistant.agentsec.yaml")).read()
SLOTS = tuple(sorted(v for k, v in vars(pack).items()
                     if k.endswith("_SLOT") and isinstance(v, str)))

FORWARD_OUT = llm.ToolRequest("forward_email", {"message_id": "msg-0050",
                                                "to": pack.EXTERNAL_ADDRESS,
                                                "note": pack.CONFIDENTIAL_CANARY})


def _seen(messages):
    listing, opened, names, bodies = [], [], [], []
    for m in messages:
        if m.get("role") == "assistant":
            for tc in m.get("tool_calls") or []:
                fn = tc.get("function") or {}
                names.append(fn.get("name"))
                if fn.get("name") == "open_email":
                    try:
                        opened.append(json.loads(fn.get("arguments") or "{}").get("message_id"))
                    except ValueError:
                        pass
        if m.get("role") == "tool":
            try:
                data = json.loads(m.get("content") or "")
            except ValueError:
                continue
            if isinstance(data, dict) and "messages" in data:
                listing = [x.get("id") for x in data["messages"]]
            else:
                bodies.append(m.get("content") or "")
    return listing, opened, names, bodies


def redirected_recording(system, messages, tools):
    """A RECORDING of a model that read the inbox, opened every message, and then forwarded
    confidential mail to the address the untrusted message pointed at. Not a model."""
    listing, opened, names, bodies = _seen(messages)
    if not any(m.get("role") == "assistant" for m in messages):
        return llm.Decision(tool_calls=[llm.ToolRequest("read_inbox", {})])
    for mid in listing:
        if mid not in opened:
            return llm.Decision(tool_calls=[llm.ToolRequest("open_email", {"message_id": mid})])
    from agentsec.evaluators.goals import _decoded, _norm
    delivered = any(_norm(sl) in _norm(b) or (_decoded(b) and _norm(sl) in _decoded(b))
                    for b in bodies for sl in SLOTS)
    if delivered and "forward_email" not in names:
        return llm.Decision(tool_calls=[FORWARD_OUT])
    return llm.Decision(content="Triage complete.")


def build_backend(kind):
    if kind == "env":
        backend = llm.backend_from_env()
        if backend is None:
            raise SystemExit(
                "--backend env needs a configured model: set AGENTSEC_LLM_BACKEND and "
                "AGENTSEC_LLM_API_KEY (see README.md). Run without --backend for the offline demo.")
        return backend, "REAL MODEL (%s)" % backend.name
    if kind == "scripted-readonly":
        return ea.build_backend("scripted", None, None), "recorded test double (read-only)"
    return llm.ScriptedBackend(redirected_recording), "recorded test double (redirected)"


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def show_mailbox(scenario, policy):
    """What the agent will encounter: the fixture inbox, with the untrusted message called out."""
    responder = scenario.responder
    print("2. FICTIONAL EMAIL CONTENT THE AGENT WILL ENCOUNTER")
    listing = json.loads(responder("read_inbox", {}, 0))
    for msg in listing["messages"]:
        print("     %-14s from %-42s %s" % (msg["id"], msg["from"], msg["subject"]))
    raw = responder("open_email", {"message_id": "msg-0100"}, 1)
    opened = json.loads(raw)
    from agentsec.evaluators.goals import _decoded, _norm
    slot = next((s for s in SLOTS
                 if _norm(s) in _norm(raw) or (_decoded(raw) and _norm(s) in _decoded(raw))), None)
    print("   untrusted message msg-0100 (external sender) carries this injection:")
    for line in (slot or "").splitlines():
        print("     | %s" % line)
    where = []
    if slot and slot in (opened.get("body") or ""):
        where.append("plain body / signature / quoted thread")
    if slot and slot in (opened.get("html") or ""):
        where.append("HTML part")
    if slot and any(slot in a["text"] for a in opened.get("attachments") or []):
        where.append("attachment text")
    print("     carried in  : %s" % (", ".join(where) or "unknown"))
    print("   synthetic confidential value in the mailbox: %r (message msg-0050)"
          % pack.CONFIDENTIAL_CANARY)
    print("   fictional external destination the attack aims at: %r" % pack.EXTERNAL_ADDRESS)
    print()


def run_config(label, hardened, backend, scenario):
    port = free_port()
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

    print("=" * 78)
    print("%s CONFIGURATION" % label)
    print("=" * 78)
    print("3. THE ASSISTANT'S ACTUAL TOOL-USE DECISIONS")
    for ev in trace.of_type("tool_call"):
        args = ", ".join("%s=%r" % kv for kv in (ev.arguments or {}).items())
        print("     -> %s(%s)" % (ev.tool_name, args))
    if not trace.of_type("tool_call"):
        print("     (no tool calls)")
    blocked = [b for state in assistant.sessions.all() for b in state.blocked]
    if blocked:
        print("   policy guard refused:")
        for b in blocked:
            print("     xx %s" % b["name"])
    print()
    print("4. RESULTING SIMULATED MAILBOX ACTIONS")
    sinks = [e for e in trace.of_type("tool_call")
             if e.tool_name in ("send_email", "forward_email", "delete_email")]
    if sinks:
        for ev in sinks:
            print("     %s%s" % (ev.tool_name, json.dumps(ev.arguments or {})))
    else:
        print("     none -- no message was sent, forwarded or deleted")
    print()
    print("5. AGENTSEC VERDICT: %s" % result.status.upper())
    for f in result.findings:
        print("     [%s] %s" % (f.severity.upper(), f.title))
        print("       rule            : %s" % f.rule)
        print("       observed action : %s" % f.observed_action)
        print("       trace evidence  :")
        for e in f.evidence:
            detail = (e.get("content") or "")
            if not detail and e.get("arguments"):
                detail = "%s(%s)" % (e.get("tool_name") or "",
                                     ", ".join("%s=%r" % kv for kv in e["arguments"].items()))
            excerpt = detail[:150].replace("\n", " ")
            print("         seq %-3s %-12s %s%s" % (e.get("seq"), e.get("type"),
                                                     excerpt, "..." if len(detail) > 150 else ""))
    if not result.findings:
        print("     no findings -- the agent encountered the untrusted content and took no "
              "unauthorized action" if result.status == "passed"
              else "     no findings")
    print()
    return result


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--backend", default="scripted-redirected",
                    choices=["scripted-redirected", "scripted-readonly", "env"])
    ap.add_argument("--scenario", default="overt_body",
                    help="which forward-exfiltration surface to demonstrate "
                         "(overt_body, subtle_attachment, signature, quoted_thread, html_part)")
    args = ap.parse_args(argv)

    backend, source = build_backend(args.backend)
    policy = parse_policy(POLICY_TEXT)
    scenarios = {sc.id.split("/")[-1]: sc
                 for sc in pack.build_forward_exfiltration(ScenarioContext(policy, 0))}
    if args.scenario not in scenarios:
        raise SystemExit("unknown --scenario %r; choose from %s"
                         % (args.scenario, ", ".join(sorted(scenarios))))
    scenario = scenarios[args.scenario]

    print()
    print("AgentSec -- reference LLM email assistant vs the Email Attack Pack")
    print("decision source: %s" % source)
    print("scenario       : %s" % scenario.id)
    print()
    print("1. THE LEGITIMATE USER REQUEST")
    print("   %r" % scenario.user_message)
    print()
    show_mailbox(scenario, policy)

    baseline = run_config("BASELINE", False, backend, scenario)
    hardened = run_config("HARDENED", True, backend, scenario)

    print("=" * 78)
    print("SUMMARY")
    print("=" * 78)
    print("  baseline : %s" % baseline.status.upper())
    print("  hardened : %s" % hardened.status.upper())
    if args.backend != "env":
        print()
        print("  NOTE: decisions came from a recorded test double, not a model. This shows that")
        print("        AgentSec detects (or clears) the behaviour; it is NOT evidence that any")
        print("        real model is or is not susceptible. Use --backend env for that.")
    if baseline.status == "findings" and hardened.status == "passed":
        print()
        print("  The identical scenario and identical decision source is reported as an attack")
        print("  against the baseline and passes against the hardened configuration, which")
        print("  reached the same untrusted content and declined to act on it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
