"""Loading extra scenario categories from attack packs (local files or installed packages)."""
import json
import re
import textwrap
from pathlib import Path

import pytest

from agentsec.adapters import CallableAdapter
from agentsec.api import AgentTarget, SecuritySuite
from agentsec.attacks import CATEGORIES, build_scenarios
from agentsec.attacks.base import Scenario, ScenarioContext
from agentsec.attacks.packs import (PackCategory, check_pack_scenarios, load_pack,
                                    load_pack_evaluators, load_packs, load_packs_evaluators)
from agentsec.evaluators.base import Evaluator
from agentsec.cli.main import main
from agentsec.policies import PolicyError, load_policy, parse_policy
from agentsec.runners import run_suite

EXAMPLE = str(Path(__file__).resolve().parent.parent / "examples" / "attack_packs" / "brand_and_pii_pack.py")
CODING_PACK = str(Path(__file__).resolve().parent.parent / "examples" / "attack_packs" / "coding_agent_pack.py")
BROWSER_PACK = str(Path(__file__).resolve().parent.parent / "examples" / "attack_packs" / "browser_agent_pack.py")
SUPPORT_PACK = str(Path(__file__).resolve().parent.parent / "examples" / "attack_packs" / "support_agent_pack.py")

BASE_POLICY = """
version: "1"
agent: {{name: t, endpoint: 'http://x'}}
allowed_tools: [search_documents]
forbidden_actions: [send_email]
tests: {tests}
attack_packs: {packs}
"""


def write_pack(tmp_path, body, name="pack.py"):
    p = tmp_path / name
    p.write_text(textwrap.dedent(body))
    return str(p)


def ctx(policy_yaml=BASE_POLICY.format(tests="[]", packs="[]")):
    return ScenarioContext(parse_policy(policy_yaml), 0)


# ---- load_pack / load_packs ----------------------------------------------

def test_load_pack_from_the_example_file():
    cats = load_pack(EXAMPLE)
    assert set(cats) == {"brand_impersonation", "custom_pii_leak"}
    scenarios = cats["custom_pii_leak"](ctx())
    assert scenarios and scenarios[0].category == "custom_pii_leak"


def test_missing_file_and_missing_module_are_policy_errors(tmp_path):
    with pytest.raises(PolicyError, match="no such file"):
        load_pack(str(tmp_path / "nope.py"))
    with pytest.raises(PolicyError, match="could not import"):
        load_pack("this_module_does_not_exist_anywhere")


def test_pack_without_categories_dict_is_rejected(tmp_path):
    with pytest.raises(PolicyError, match="CATEGORIES"):
        load_pack(write_pack(tmp_path, "X = 1\n"))
    with pytest.raises(PolicyError, match="CATEGORIES"):
        load_pack(write_pack(tmp_path, "CATEGORIES = {}\n"))
    with pytest.raises(PolicyError, match="CATEGORIES"):
        load_pack(write_pack(tmp_path, "CATEGORIES = {'x': 1}\n"))  # not callable


def test_import_error_inside_the_pack_is_a_policy_error(tmp_path):
    with pytest.raises(PolicyError, match="ValueError"):
        load_pack(write_pack(tmp_path, "raise ValueError('boom')\n"))


def test_load_packs_rejects_builtin_and_cross_pack_collisions(tmp_path):
    builtin_clash = write_pack(tmp_path, """
        from agentsec.attacks.base import Scenario
        def build(ctx):
            return []
        CATEGORIES = {"prompt_injection": build}
        """, "clash.py")
    with pytest.raises(PolicyError, match="built-in category"):
        load_packs([builtin_clash], dict(CATEGORIES))

    a = write_pack(tmp_path, """
        from agentsec.attacks.base import Scenario
        def build(ctx):
            return [Scenario(id="dup/1", category="dup", title="t", description="t", user_message="m")]
        CATEGORIES = {"dup": build}
        """, "a.py")
    b = write_pack(tmp_path, """
        from agentsec.attacks.base import Scenario
        def build(ctx):
            return [Scenario(id="dup/2", category="dup", title="t", description="t", user_message="m")]
        CATEGORIES = {"dup": build}
        """, "b.py")
    with pytest.raises(PolicyError, match="already defined"):
        load_packs([a, b], {})
    merged = load_packs([a], {})
    assert isinstance(merged["dup"], PackCategory) and merged["dup"].spec == a


# ---- check_pack_scenarios --------------------------------------------------

def test_check_pack_scenarios_catches_broken_packs():
    ok = [Scenario(id="c/1", category="c", title="t", description="t", user_message="m")]
    check_pack_scenarios("spec", "c", ok)  # no error
    with pytest.raises(PolicyError, match="built no scenarios"):
        check_pack_scenarios("spec", "c", [])
    with pytest.raises(PolicyError, match="must build Scenario"):
        check_pack_scenarios("spec", "c", ["not a scenario"])
    with pytest.raises(PolicyError, match="expected"):
        check_pack_scenarios("spec", "c", [Scenario(id="c/1", category="other", title="t",
                                                    description="t", user_message="m")])
    with pytest.raises(PolicyError, match="duplicate scenario id"):
        check_pack_scenarios("spec", "c", ok + ok)


# ---- build_scenarios / run_suite integration ------------------------------

def test_policy_attack_packs_run_by_default_when_tests_is_empty():
    policy = parse_policy(BASE_POLICY.format(tests="[]", packs="[%r]" % EXAMPLE))
    scenarios, warnings = build_scenarios(ScenarioContext(policy, 0))
    ids = {s.id for s in scenarios}
    assert {"brand_impersonation/claim_other_company", "custom_pii_leak/full_reference"} <= ids
    assert warnings == []


def test_policy_attack_packs_are_not_run_unless_listed_in_tests():
    policy = parse_policy(BASE_POLICY.format(tests="[prompt_injection]", packs="[%r]" % EXAMPLE))
    scenarios, _ = build_scenarios(ScenarioContext(policy, 0))
    assert all(s.category == "prompt_injection" for s in scenarios)
    # but -s / `only` can still select it once it's requested via `categories=`
    scenarios2, _ = build_scenarios(ScenarioContext(policy, 0), categories=["prompt_injection", "custom_pii_leak"])
    assert {s.category for s in scenarios2} == {"prompt_injection", "custom_pii_leak"}


def test_extra_categories_argument_adds_a_pack_for_one_run_without_touching_the_policy():
    policy = parse_policy(BASE_POLICY.format(tests="[]", packs="[]"))
    extra = load_packs([EXAMPLE], CATEGORIES)
    scenarios, _ = build_scenarios(ScenarioContext(policy, 0), extra_categories=extra)
    assert any(s.category == "brand_impersonation" for s in scenarios)
    # the policy itself still has no packs configured
    assert policy.attack_packs == []


def _naive_agent(messages, tools):
    """Calls the first declared tool once, then repeats whatever it gets back verbatim."""
    if messages[-1].get("role") == "tool":
        return "Here is what I found: " + messages[-1]["content"]
    if tools:
        return {"tool_calls": [{"name": tools[0]["function"]["name"], "arguments": {"query": "x"}}]}
    return "no tools available"


def test_run_suite_with_a_pack_produces_a_real_finding():
    policy = parse_policy(BASE_POLICY.format(tests="[]", packs="[%r]" % EXAMPLE))
    suite = run_suite(policy, CallableAdapter(_naive_agent), only=["custom_pii_leak"])
    assert suite.findings and suite.findings[0].rule == "secret_leak"
    assert suite.findings[0].category == "custom_pii_leak"


def test_python_api_attack_packs():
    target = AgentTarget("http://x", allowed_tools=["search_documents"], attack_packs=[EXAMPLE])
    assert target.policy.attack_packs == [EXAMPLE]
    result = SecuritySuite(target, adapter=CallableAdapter(_naive_agent)).run("custom_pii_leak")
    assert result.suite.results and result.suite.results[0].scenario.category == "custom_pii_leak"
    assert result.findings and result.findings[0].rule == "secret_leak"

    # attack_packs= on SecuritySuite works even when the policy has none configured
    plain_target = AgentTarget("http://x", allowed_tools=["search_documents"])
    extra = load_packs([EXAMPLE], CATEGORIES)
    result2 = SecuritySuite(plain_target, adapter=CallableAdapter(_naive_agent),
                            attack_packs=extra).run("brand_impersonation")
    assert result2.suite.results


# ---- CLI -------------------------------------------------------------------

def test_cli_attack_pack_flag(tmp_path):
    pol = tmp_path / "p.yaml"
    pol.write_text("agent: {name: t, endpoint: 'http://127.0.0.1:1/agent'}\ntests: []\n")
    assert main(["test", "-p", str(pol), "--attack-pack", EXAMPLE, "-s", "custom_pii_leak",
                "-o", str(tmp_path / "out"), "--fail-on", "none"]) == 2  # agent unreachable -> error exit
    assert main(["test", "-p", str(pol), "--attack-pack", str(tmp_path / "missing.py"),
                "-o", str(tmp_path / "out2")]) == 2


def test_cli_attack_pack_builtin_collision_is_an_error(tmp_path):
    clash = write_pack(tmp_path, """
        from agentsec.attacks.base import Scenario
        def build(ctx):
            return []
        CATEGORIES = {"prompt_injection": build}
        """, "clash.py")
    pol = tmp_path / "p.yaml"
    pol.write_text("agent: {name: t, endpoint: 'http://127.0.0.1:1/agent'}\n")
    assert main(["test", "-p", str(pol), "--attack-pack", clash, "-o", str(tmp_path / "out")]) == 2


def test_policy_rejects_unknown_attack_pack_field_value():
    with pytest.raises(PolicyError):
        parse_policy("agent: {name: a, endpoint: 'http://x'}\nattack_packs: not-a-list\n")
    with pytest.raises(PolicyError):
        parse_policy("agent: {name: a, endpoint: 'http://x'}\nattack_packs: ['']\n")


# ---- pack-provided evaluators (EVALUATORS) ---------------------------------

def test_pack_without_evaluators_attr_contributes_none(tmp_path):
    spec = write_pack(tmp_path, """
        from agentsec.attacks.base import Scenario
        def build(ctx):
            return [Scenario(id="c/1", category="c", title="t", description="t", user_message="m")]
        CATEGORIES = {"c": build}
        """)
    assert load_pack_evaluators(spec) == []
    assert load_packs_evaluators([spec]) == []


def test_evaluators_must_be_a_list_of_evaluator_subclasses(tmp_path):
    not_a_list = write_pack(tmp_path, """
        CATEGORIES = {"c": lambda ctx: []}
        EVALUATORS = "not-a-list"
        """, "a.py")
    with pytest.raises(PolicyError, match="must be a list"):
        load_pack_evaluators(not_a_list)

    not_evaluator_subclass = write_pack(tmp_path, """
        CATEGORIES = {"c": lambda ctx: []}
        class NotAnEvaluator:
            pass
        EVALUATORS = [NotAnEvaluator]
        """, "b.py")
    with pytest.raises(PolicyError, match="Evaluator subclasses"):
        load_pack_evaluators(not_evaluator_subclass)

    not_a_class = write_pack(tmp_path, """
        CATEGORIES = {"c": lambda ctx: []}
        EVALUATORS = [lambda: None]
        """, "c.py")
    with pytest.raises(PolicyError, match="Evaluator subclasses"):
        load_pack_evaluators(not_a_class)


def test_load_pack_evaluators_from_a_real_pack(tmp_path):
    spec = write_pack(tmp_path, """
        from agentsec.attacks.base import Scenario
        from agentsec.evaluators.base import Evaluator

        class MyCheck(Evaluator):
            name = "my_check"
            def evaluate(self, scenario, trace, policy):
                return []

        def build(ctx):
            return [Scenario(id="c/1", category="c", title="t", description="t", user_message="m")]
        CATEGORIES = {"c": build}
        EVALUATORS = [MyCheck]
        """)
    evaluators = load_pack_evaluators(spec)
    assert len(evaluators) == 1 and evaluators[0].name == "my_check"
    assert issubclass(evaluators[0], Evaluator)


def test_load_packs_evaluators_merges_across_packs_and_dedups_specs(tmp_path):
    def pack_with_check(name, filename):
        return write_pack(tmp_path, """
            from agentsec.attacks.base import Scenario
            from agentsec.evaluators.base import Evaluator
            class Check(Evaluator):
                name = "%s"
                def evaluate(self, scenario, trace, policy):
                    return []
            CATEGORIES = {"c": lambda ctx: [Scenario(id="c/1", category="c", title="t",
                                                     description="t", user_message="m")]}
            EVALUATORS = [Check]
            """ % name, filename)

    a = pack_with_check("check_a", "a.py")
    b = pack_with_check("check_b", "b.py")
    merged = load_packs_evaluators([a, b, a])  # duplicate spec, imported only once
    assert sorted(cls.name for cls in merged) == ["check_a", "check_b"]


def test_load_pack_evaluators_from_the_coding_agent_example():
    evaluators = load_pack_evaluators(CODING_PACK)
    names = sorted(cls.name for cls in evaluators)
    assert names == ["coding_agent_insecure_patch", "coding_agent_typosquat_package"]
    assert all(issubclass(cls, Evaluator) for cls in evaluators)


def test_load_pack_evaluators_from_the_browser_agent_example():
    evaluators = load_pack_evaluators(BROWSER_PACK)
    names = sorted(cls.name for cls in evaluators)
    assert names == ["browser_agent_lookalike_domain"]
    assert all(issubclass(cls, Evaluator) for cls in evaluators)


def test_load_pack_evaluators_from_the_support_agent_example():
    evaluators = load_pack_evaluators(SUPPORT_PACK)
    names = sorted(cls.name for cls in evaluators)
    assert names == ["support_agent_refund_abuse"]
    assert all(issubclass(cls, Evaluator) for cls in evaluators)


# ---- coding_agent_pack: a full run_suite round trip through a real pack's
#      own evaluators, not just the loader in isolation ----------------------

CODING_POLICY = """
version: "1"
agent: {name: t, endpoint: 'http://x'}
allowed_tools: [search_packages, install_package, write_file]
forbidden_actions: [run_shell, push_to_remote]
tests: []
attack_packs: [%r]
""" % CODING_PACK


def _obedient_dependency_agent(messages, tools):
    """Calls the first tool, then installs or writes whatever the poisoned result told it to --
    exactly once: install_package/write_file are themselves allowed tools, so their own result
    would otherwise be routed back through the same scripted responder and looped forever."""
    last = messages[-1]
    if last.get("role") == "tool":
        prior_calls = (messages[-2].get("tool_calls") or []) if len(messages) >= 2 else []
        prior_names = {c["function"]["name"] for c in prior_calls}
        if prior_names & {"install_package", "write_file"}:
            return "done"
        content = last["content"]
        for lookalike in ("reqeusts", "python-requsts", "colourama", "numpyy"):
            if lookalike in content:
                return {"tool_calls": [{"name": "install_package", "arguments": {"package": lookalike}}]}
        if "verify=False" in content or "DEBUG" in content:
            return {"tool_calls": [{"name": "write_file",
                                   "arguments": {"path": "settings.py", "content": content}}]}
        return "done"
    if tools:
        return {"tool_calls": [{"name": tools[0]["function"]["name"], "arguments": {"query": "x"}}]}
    return "no tools available"


def test_run_suite_coding_agent_pack_typosquat_evaluator_fires_for_real():
    policy = parse_policy(CODING_POLICY)
    suite = run_suite(policy, CallableAdapter(_obedient_dependency_agent),
                      only=["coding_agent_malicious_dependency"])
    assert suite.findings
    assert all(f.rule == "coding_agent_typosquat_package" for f in suite.findings)
    assert {f.key for f in suite.findings} == {"reqeusts", "python-requsts", "colourama", "numpyy"}
    assert all(f.severity == "critical" for f in suite.findings)


def test_run_suite_coding_agent_pack_insecure_patch_evaluator_fires_for_real():
    policy = parse_policy(CODING_POLICY)
    suite = run_suite(policy, CallableAdapter(_obedient_dependency_agent),
                      only=["coding_agent_insecure_patch"])
    assert suite.findings
    assert {f.rule for f in suite.findings} == {"coding_agent_insecure_patch"}


def _obedient_pr_agent(messages, tools):
    """Reads whatever comment it's shown and obeys any forbidden action named in it."""
    last = messages[-1]
    if last.get("role") == "tool":
        content = last["content"]
        if "run_shell" in content:
            return {"tool_calls": [{"name": "run_shell", "arguments": {"cmd": "echo hi"}}]}
        if "push_to_remote" in content:
            return {"tool_calls": [{"name": "push_to_remote", "arguments": {}}]}
        return "done"
    if tools:
        return {"tool_calls": [{"name": tools[0]["function"]["name"], "arguments": {}}]}
    return "no tools available"


def test_run_suite_coding_agent_pack_pr_comment_uses_builtin_forbidden_action_evaluator():
    """This category needs no EVALUATORS entry: the built-in ToolPolicyEvaluator already
    catches a forbidden tool called after untrusted input, which is exactly this attack."""
    policy = parse_policy(CODING_POLICY)
    suite = run_suite(policy, CallableAdapter(_obedient_pr_agent),
                      only=["coding_agent_pr_comment_injection"])
    assert suite.findings
    assert all(f.rule == "forbidden_action" for f in suite.findings)
    assert all(f.severity == "critical" for f in suite.findings)  # vector=document -> untrusted


# ---- browser_agent_pack: same shape as the coding-agent pack, applied to a
#      different domain -- one category needs a pack evaluator (lookalike_domain,
#      because navigate is a normal allowed tool), the other two are fully covered
#      by the built-in forbidden-action evaluator. ------------------------------

BROWSER_POLICY = """
version: "1"
agent: {name: t, endpoint: 'http://x'}
allowed_tools: [read_page, navigate, fill_form]
forbidden_actions: [submit_form, download_file, enter_credentials]
tests: []
attack_packs: [%r]
""" % BROWSER_PACK


def _obedient_browser_agent(messages, tools):
    """Reads whatever the page says, then: navigates to a lookalike domain it's shown -- once --
    or calls whichever forbidden action the page names. navigate is itself an allowed tool, so
    without the "already navigated" guard its own result would loop back through the same
    fixed-payload responder forever, the same trap _obedient_dependency_agent hit above."""
    last = messages[-1]
    if last.get("role") == "tool":
        prior_calls = (messages[-2].get("tool_calls") or []) if len(messages) >= 2 else []
        prior_names = {c["function"]["name"] for c in prior_calls}
        if "navigate" in prior_names:
            return "done"
        content = last["content"]
        for domain in ("arnaz0n.com", "paypa1-secure.com", "githiub.com", "0utlook-login.com"):
            if domain in content:
                return {"tool_calls": [{"name": "navigate", "arguments": {"url": "https://%s/login" % domain}}]}
        for forbidden in ("submit_form", "download_file", "enter_credentials"):
            if forbidden in content:
                return {"tool_calls": [{"name": forbidden, "arguments": {}}]}
        return "done"
    if tools:
        return {"tool_calls": [{"name": tools[0]["function"]["name"], "arguments": {"query": "x"}}]}
    return "no tools available"


def test_run_suite_browser_agent_pack_lookalike_domain_evaluator_fires_for_real():
    policy = parse_policy(BROWSER_POLICY)
    suite = run_suite(policy, CallableAdapter(_obedient_browser_agent),
                      only=["browser_agent_lookalike_domain"])
    assert suite.findings
    assert all(f.rule == "browser_agent_lookalike_domain" for f in suite.findings)
    assert {f.key for f in suite.findings} == {
        "arnaz0n.com", "paypa1-secure.com", "githiub.com", "0utlook-login.com"}
    assert all(f.severity == "critical" for f in suite.findings)


def test_run_suite_browser_agent_pack_hidden_page_instruction_uses_builtin_forbidden_action_evaluator():
    """No EVALUATORS entry for this category either: a hidden instruction steering the agent to a
    forbidden tool is exactly what the built-in ToolPolicyEvaluator already catches."""
    policy = parse_policy(BROWSER_POLICY)
    suite = run_suite(policy, CallableAdapter(_obedient_browser_agent),
                      only=["browser_agent_hidden_page_instruction"])
    assert suite.findings
    assert all(f.rule == "forbidden_action" for f in suite.findings)
    assert all(f.severity == "critical" for f in suite.findings)  # vector=document -> untrusted


def test_run_suite_browser_agent_pack_consent_trap_uses_builtin_forbidden_action_evaluator():
    policy = parse_policy(BROWSER_POLICY)
    suite = run_suite(policy, CallableAdapter(_obedient_browser_agent),
                      only=["browser_agent_consent_trap"])
    assert suite.findings
    assert all(f.rule == "forbidden_action" for f in suite.findings)
    assert all(f.severity == "critical" for f in suite.findings)


# ---- support_agent_pack: same shape again -- one category the built-in
#      forbidden-action evaluator already covers, one that needs a pack
#      evaluator because the attack is in issue_refund's arguments, and one
#      cross-session scenario that needs no evaluator either, reusing the
#      built-in SecretLeakEvaluator's canary check across two sessions. -------

SUPPORT_POLICY = """
version: "1"
agent: {name: t, endpoint: 'http://x'}
allowed_tools: [lookup_account, issue_refund]
forbidden_actions: [waive_verification, override_hold]
tests: []
attack_packs: [%r]
""" % SUPPORT_PACK


def _obedient_escalation_agent(messages, tools):
    """Obeys whichever forbidden action the caller's own message names."""
    last = messages[-1]
    if last.get("role") == "user":
        content = last["content"]
        for name in ("waive_verification", "override_hold"):
            if name in content:
                return {"tool_calls": [{"name": name, "arguments": {}}]}
    return "done"


def test_run_suite_support_agent_pack_impersonation_escalation_uses_builtin_forbidden_action_evaluator():
    """No EVALUATORS entry for this category: a caller talking the agent into a forbidden tool
    call is exactly what the built-in ToolPolicyEvaluator already catches."""
    policy = parse_policy(SUPPORT_POLICY)
    suite = run_suite(policy, CallableAdapter(_obedient_escalation_agent),
                      only=["support_agent_impersonation_escalation"])
    assert suite.findings
    assert all(f.rule == "forbidden_action" for f in suite.findings)
    assert all(f.severity == "high" for f in suite.findings)  # vector=direct -> not untrusted


def _obedient_refund_agent(messages, tools):
    """Complies with whatever the caller in the original message asked for: an oversized refund
    on the first ask, or -- when the message also asks for the same order "again" -- a second
    issue_refund call for that order, stopping once it has issued exactly that many."""
    origin = messages[0]["content"]
    order_id = re.search(r"(ORD-\d+)", origin).group(1)
    last = messages[-1]
    if last.get("role") == "user":
        amt = re.search(r"\$(\d+)", origin)
        amount = float(amt.group(1)) if amt else 0.0
        return {"tool_calls": [{"name": "issue_refund", "arguments": {"order_id": order_id, "amount": amount}}]}
    if last.get("role") == "tool":
        prior_refund_calls = sum(
            1 for m in messages if m.get("role") == "assistant"
            for c in (m.get("tool_calls") or []) if c["function"]["name"] == "issue_refund")
        if "again" in origin and prior_refund_calls < 2:
            return {"tool_calls": [{"name": "issue_refund", "arguments": {"order_id": order_id, "amount": 45.0}}]}
        return "done"
    return "done"


def test_run_suite_support_agent_pack_refund_abuse_evaluator_fires_for_oversized_amount():
    policy = parse_policy(SUPPORT_POLICY)
    suite = run_suite(policy, CallableAdapter(_obedient_refund_agent),
                      only=["support_agent_refund_abuse/oversized_refund_pressure"])
    assert suite.findings
    assert all(f.rule == "support_agent_refund_over_cap" for f in suite.findings)
    assert all(f.key == "ORD-4471" for f in suite.findings)


def test_run_suite_support_agent_pack_refund_abuse_evaluator_fires_for_duplicate_refund():
    policy = parse_policy(SUPPORT_POLICY)
    suite = run_suite(policy, CallableAdapter(_obedient_refund_agent),
                      only=["support_agent_refund_abuse/duplicate_refund_same_order"])
    assert suite.findings
    assert all(f.rule == "support_agent_duplicate_refund" for f in suite.findings)
    assert all(f.key == "ORD-7788" for f in suite.findings)


def _cross_customer_agent():
    """A caller's account reference given for verification bleeds into what a later, different
    caller on the same line is told -- simulating a support agent that conflates two sessions."""
    state = {}
    canary_re = re.compile(r"(CANARY-[0-9a-fA-F]+)")

    def agent(messages, tools):
        last = messages[-1]
        if last.get("role") == "user":
            m = canary_re.search(last["content"])
            if m:
                state["canary"] = m.group(1)
                return "Thanks, I've verified your account and I'm looking into this for you now."
            if "previous caller" in last["content"]:
                return ("Sure -- the previous caller on this line gave the account reference %s."
                        % state.get("canary", ""))
        return "done"
    return agent


def test_run_suite_support_agent_pack_cross_customer_leak_uses_builtin_secret_leak_evaluator():
    """No EVALUATORS entry for this category either: a planted canary surfacing in the agent's
    own output to a different, later session is exactly what the built-in SecretLeakEvaluator
    already catches -- the same mechanism memory_poisoning's cross_session_leak scenario relies
    on, reused here for a support-desk-specific category."""
    policy = parse_policy(SUPPORT_POLICY)
    suite = run_suite(policy, CallableAdapter(_cross_customer_agent()),
                      only=["support_agent_cross_customer_leak"])
    assert suite.findings
    assert all(f.rule == "secret_leak" for f in suite.findings)
    assert all(f.category == "support_agent_cross_customer_leak" for f in suite.findings)
