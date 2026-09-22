"""Loading extra scenario categories from attack packs (local files or installed packages)."""
import json
import textwrap
from pathlib import Path

import pytest

from agentsec.adapters import CallableAdapter
from agentsec.api import AgentTarget, SecuritySuite
from agentsec.attacks import CATEGORIES, build_scenarios
from agentsec.attacks.base import Scenario, ScenarioContext
from agentsec.attacks.packs import PackCategory, check_pack_scenarios, load_pack, load_packs
from agentsec.cli.main import main
from agentsec.policies import PolicyError, load_policy, parse_policy
from agentsec.runners import run_suite

EXAMPLE = str(Path(__file__).resolve().parent.parent / "examples" / "attack_packs" / "brand_and_pii_pack.py")

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
