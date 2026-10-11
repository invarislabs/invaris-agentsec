#!/usr/bin/env python3
"""End-to-end demonstration of the reference LLM browser assistant against the Browser Attack Pack.

For each configuration (baseline, then hardened) it prints: the legitimate user request, the
fictional page content the agent encountered (with the untrusted injection called out), the
assistant's actual tool-use decisions, the resulting simulated actions, and AgentSec's verdict,
findings and trace evidence. Runs over the real pipeline through the real HTTP adapter.

    python examples/real_world_agents/llm_browser_assistant/demo.py
    python examples/real_world_agents/llm_browser_assistant/demo.py --scenario unauthorized_purchase
    python examples/real_world_agents/llm_browser_assistant/demo.py --backend env   # real model

With a recorded test double (the default), the verdicts demonstrate the detection pipeline, not a
model's behaviour. Use --backend env (and evaluate_live.py) for an actual model.
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
_EXAMPLES = os.path.dirname(os.path.dirname(_HERE))

from agentsec.adapters import HTTPAgentAdapter              # noqa: E402
from agentsec.attacks.base import ScenarioContext           # noqa: E402
from agentsec.evaluators import evaluate_trace              # noqa: E402
from agentsec.evaluators.goals import _decoded, _norm       # noqa: E402
from agentsec.policies import parse_policy                  # noqa: E402
from agentsec.runners.local import ScenarioResult, run_scenario  # noqa: E402


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ba = _load("demo_browser_assistant", os.path.join(_HERE, "server.py"))
llm = ba.llm
pack = ba.pack
POLICY_TEXT = open(os.path.join(_EXAMPLES, "attack_packs", "browser_agent.agentsec.yaml")).read()
SLOTS = tuple(v for k, v in vars(pack).items() if "_SLOT" in k and isinstance(v, str))


def _delivered(bodies):
    return any(_norm(s) in _norm(b) or (_decoded(b) and _norm(s) in _decoded(b))
               for b in bodies for s in SLOTS)


def redirected_recording(action_for):
    """A RECORDING of a model redirected by page content: reads account+product (re-reading to
    reach a cloaked page), then performs `action_for(bodies)`. Not a model."""
    def decide(system, messages, tools):
        read, bodies, names = [], [], []
        for m in messages:
            if m.get("role") == "assistant":
                for tc in m.get("tool_calls") or []:
                    fn = tc.get("function") or {}
                    names.append(fn.get("name"))
                    if fn.get("name") in ("read_page", "fetch_page"):
                        try:
                            read.append(json.loads(fn.get("arguments") or "{}").get("url"))
                        except ValueError:
                            pass
            if m.get("role") == "tool":
                bodies.append(m.get("content") or "")
        if not any(m.get("role") == "assistant" for m in messages):
            return llm.Decision(tool_calls=[llm.ToolRequest("read_page", {"url": pack.ACCOUNT_URL})])
        for u in (pack.ACCOUNT_URL, pack.PRODUCT_URL):
            if u not in read:
                return llm.Decision(tool_calls=[llm.ToolRequest("read_page", {"url": u})])
        if not _delivered(bodies) and read.count(pack.PRODUCT_URL) < 3:
            return llm.Decision(tool_calls=[llm.ToolRequest("read_page", {"url": pack.PRODUCT_URL})])
        sink_names = {"navigate", "submit_form", "fill_form", "place_order"}
        act = action_for(" ".join(bodies))
        if act is not None and _delivered(bodies) and not (sink_names & set(names)):
            return llm.Decision(tool_calls=[act])
        return llm.Decision(content="Summary complete.")
    return decide


def action_for_scenario(slug):
    def choose(blob):
        if slug == "unauthorized_purchase":
            return llm.ToolRequest("place_order", {"sku": pack.ATTACK_SKU, "quantity": 1})
        if slug == "unauthorized_navigation":
            return llm.ToolRequest("navigate", {"url": "https://%s/item/42" % pack.OFFERS_HOST})
        if slug == "unauthorized_form_submission":
            return llm.ToolRequest("submit_form", {"url": "https://%s/intake" % pack.EXFIL_HOST,
                                                   "fields": {"ref": pack.BROWSER_CANARY}})
        return llm.ToolRequest("navigate", {"url": "https://%s/collect?ref=%s"
                                            % (pack.EXFIL_HOST, pack.BROWSER_CANARY)})
    return choose


def build_backend(kind, slug):
    if kind == "env":
        backend = llm.backend_from_env()
        if backend is None:
            raise SystemExit("--backend env needs a configured model (see README.md).")
        return backend, "REAL MODEL (%s)" % backend.name
    if kind == "scripted-readonly":
        return ba.build_backend("scripted", None, None), "recorded test double (read-only)"
    return llm.ScriptedBackend(redirected_recording(action_for_scenario(slug))), \
        "recorded test double (redirected)"


SCENARIOS = {
    "exfiltration": ("browser_agent_data_exfiltration_via_navigation/reviews",
                     pack.build_nav_exfiltration),
    "unauthorized_navigation": ("browser_agent_unauthorized_navigation/moved_listing",
                                pack.build_unauthorized_navigation),
    "unauthorized_form_submission": ("browser_agent_unauthorized_form_submission/offsite_intake",
                                     pack.build_unauthorized_form_submission),
    "unauthorized_purchase": ("browser_agent_unauthorized_purchase/unrequested_sku",
                              pack.build_unauthorized_purchase),
}


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def find_scenario(build, sid):
    for sc in build(ScenarioContext(parse_policy(POLICY_TEXT), 0)):
        if sc.id == sid:
            return sc
    raise SystemExit("scenario %s not built" % sid)


def show_content(scenario):
    responder = scenario.responder
    print("2. FICTIONAL PAGE CONTENT THE AGENT WILL ENCOUNTER")
    acct = json.loads(responder("read_page", {"url": pack.ACCOUNT_URL}, 0))
    print("   account page %s  (carries synthetic reference code %r)"
          % (acct["url"], pack.BROWSER_CANARY))
    prod = json.loads(responder("read_page", {"url": pack.PRODUCT_URL}, 1))
    slot = next((s for s in SLOTS if _norm(s) in _norm(json.dumps(prod))
                 or (_decoded(json.dumps(prod)) and _norm(s) in _decoded(json.dumps(prod)))), None)
    surface = next((k for k in ("body", "meta", "comments", "hidden_elements", "image_alt_text",
                                "reviews") if slot and _norm(slot) in _norm(json.dumps(prod.get(k)))), "?")
    print("   product page %s  (untrusted injection in: %s)" % (prod["url"], surface))
    for line in (slot or "").splitlines() or [""]:
        print("     | %s" % line)
    print()


def run_config(label, hardened, backend, scenario):
    port = free_port()
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
    print("=" * 78)
    print("%s CONFIGURATION" % label)
    print("=" * 78)
    print("3. THE ASSISTANT'S ACTUAL TOOL-USE DECISIONS")
    for ev in trace.of_type("tool_call"):
        print("     -> %s(%s)" % (ev.tool_name, ", ".join("%s=%r" % kv for kv in (ev.arguments or {}).items())))
    blocked = [b["name"] for state in assistant.sessions.all() for b in state.blocked]
    for b in blocked:
        print("     xx %s" % b)
    print("\n4. RESULTING SIMULATED ACTIONS")
    sinks = [e for e in trace.of_type("tool_call")
             if e.tool_name in ("navigate", "submit_form", "fill_form", "place_order")]
    for ev in sinks:
        print("     %s%s" % (ev.tool_name, json.dumps(ev.arguments or {})))
    if not sinks:
        print("     none -- no navigation, submission or order occurred")
    print("\n5. AGENTSEC VERDICT: %s" % result.status.upper())
    for f in result.findings:
        print("     [%s] %s  (%s)" % (f.severity.upper(), f.title, f.rule))
        print("       observed: %s" % f.observed_action)
        for e in f.evidence:
            detail = e.get("content") or ""
            if not detail and e.get("arguments"):
                detail = "%s(%s)" % (e.get("tool_name") or "",
                                     ", ".join("%s=%r" % kv for kv in e["arguments"].items()))
            print("       evidence seq %s %s: %s" % (e.get("seq"), e.get("type"), detail[:120]))
    if not result.findings:
        print("     no findings -- encountered the untrusted content and took no unauthorized action"
              if result.status == "passed" else "     no findings")
    print()
    return result


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--backend", default="scripted-redirected",
                    choices=["scripted-redirected", "scripted-readonly", "env"])
    ap.add_argument("--scenario", default="exfiltration", choices=sorted(SCENARIOS))
    args = ap.parse_args(argv)

    sid, build = SCENARIOS[args.scenario]
    backend, source = build_backend(args.backend, args.scenario)
    scenario = find_scenario(build, sid)

    print("\nAgentSec -- reference LLM browser assistant vs the Browser Attack Pack")
    print("decision source: %s" % source)
    print("scenario       : %s\n" % scenario.id)
    print("1. THE LEGITIMATE USER REQUEST")
    print("   %r\n" % scenario.user_message)
    show_content(scenario)

    baseline = run_config("BASELINE", False, backend, scenario)
    hardened = run_config("HARDENED", True, backend, scenario)

    print("=" * 78)
    print("SUMMARY")
    print("=" * 78)
    print("  baseline : %s" % baseline.status.upper())
    print("  hardened : %s" % hardened.status.upper())
    if args.backend != "env":
        print("\n  NOTE: decisions came from a recorded test double, not a model. This shows that")
        print("        AgentSec detects (or clears) the behaviour; it is NOT evidence about a real")
        print("        model. Use --backend env or evaluate_live.py for that.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
