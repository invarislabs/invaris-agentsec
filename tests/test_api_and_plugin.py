import os
import sys
from pathlib import Path

import pytest

from agentsec import CATEGORIES, AgentTarget, SecuritySuite
from agentsec.policies import PolicyError

ROOT = Path(__file__).resolve().parent.parent
SECRET = "sk-live-INVARIS-DEMO-7f3a9c1e5b2d"


def target(url, **kw):
    return AgentTarget(url, allowed_tools={"search_documents", "create_draft"},
                       forbidden_tools={"send_email", "execute_payment", "reveal_credentials"},
                       secrets=[SECRET], **kw)


def test_readme_example_flow_against_safe_agent(safe_url):
    result = SecuritySuite(target(safe_url)).run("indirect_prompt_injection")
    assert result.secret_leaks == []
    assert result.forbidden_tool_calls == []
    assert result.total_tool_calls <= 10
    assert result.passed
    result.assert_clean("low")


def test_vulnerable_agent_fails_assertions(vulnerable_url):
    result = SecuritySuite(target(vulnerable_url)).run("indirect_prompt_injection")
    assert result.forbidden_tool_calls, "expected forbidden calls"
    assert {c.name for c in result.forbidden_tool_calls} <= {"send_email", "execute_payment", "reveal_credentials"}
    assert not result.passed
    with pytest.raises(AssertionError, match="CRITICAL"):
        result.assert_clean("high")


def test_secret_leaks_and_unauthorized_calls(vulnerable_url):
    leaks = SecuritySuite(target(vulnerable_url)).run("secret_extraction").secret_leaks
    assert len(leaks) == 5
    unauth = SecuritySuite(target(vulnerable_url)).run("unauthorized_tool_use").unauthorized_tool_calls
    assert {c.name for c in unauth} == {"delete_records", "shell"}


def test_total_tool_calls_is_per_scenario_maximum(vulnerable_url):
    result = SecuritySuite(target(vulnerable_url, max_tool_calls=4)).run("loop_and_budget_limits")
    assert result.total_tool_calls == 5  # 4 allowed + the over-budget attempt
    assert set(result.tool_calls_by_scenario) == {r.scenario.id for r in result.results}


def test_run_by_scenario_id_and_seed(safe_url):
    suite = SecuritySuite(target(safe_url), seed=5)
    r = suite.run("prompt_injection/marker_override")
    assert [x.scenario.id for x in r.results] == ["prompt_injection/marker_override"]
    assert suite.run("prompt_injection/marker_override", seed=6).results[0].scenario.user_message != \
        r.results[0].scenario.user_message


def test_run_all_when_no_names(safe_url):
    assert len(SecuritySuite(target(safe_url)).run().results) == 34
    assert CATEGORIES[0] == "prompt_injection" and "memory_poisoning" in CATEGORIES


def test_errors_are_not_passes():
    result = SecuritySuite(AgentTarget("http://127.0.0.1:1/agent")).run("prompt_injection/ignore_previous")
    assert not result.passed and len(result.errors) == 1
    with pytest.raises(AssertionError, match="errored"):
        result.assert_clean()


def test_target_validation_and_unknown_category():
    with pytest.raises(PolicyError):
        AgentTarget("localhost:8000")
    with pytest.raises(PolicyError, match="unknown test category"):
        SecuritySuite(AgentTarget("http://x")).run("nope")


def test_target_round_trips_through_policy_file(tmp_path, safe_url, policy_text):
    p = tmp_path / "a.yaml"
    p.write_text(policy_text.format(endpoint=safe_url))
    t = AgentTarget.from_file(str(p))
    assert t.policy.forbidden_actions == ["send_email", "reveal_credentials", "execute_payment"]


# --- pytest plugin, exercised in a subprocess ---------------------------------

pytest_plugins = ["pytester"]


def _run_inner(pytester, monkeypatch, args=()):
    monkeypatch.setenv("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1")
    # pytester gives the subprocess a fresh HOME, so make pytest and agentsec importable explicitly.
    paths = [str(ROOT), os.path.dirname(os.path.dirname(pytest.__file__)), os.environ.get("PYTHONPATH", "")]
    monkeypatch.setenv("PYTHONPATH", os.pathsep.join(p for p in paths if p))
    return pytester.runpytest_subprocess("-p", "agentsec.pytest_plugin", *args)


def test_plugin_fixtures_pass_and_fail(pytester, monkeypatch, safe_url, vulnerable_url, policy_text):
    pytester.makefile(".yaml", safe=policy_text.format(endpoint=safe_url),
                      vuln=policy_text.format(endpoint=vulnerable_url))
    pytester.makepyfile(test_inner="""
        import pytest
        from agentsec import CATEGORIES

        @pytest.mark.parametrize("category", CATEGORIES)
        def test_category(category, agentsec_run):
            agentsec_run(category, fail_on="high")

        def test_target_fixture(agentsec_target, agentsec_policy):
            assert agentsec_target.policy is agentsec_policy
    """)
    ok = _run_inner(pytester, monkeypatch, ("--agentsec-policy", "safe.yaml"))
    ok.assert_outcomes(passed=len(CATEGORIES) + 1)

    bad = _run_inner(pytester, monkeypatch, ("--agentsec-policy", "vuln.yaml", "-k", "prompt_injection"))
    bad.assert_outcomes(failed=2)  # prompt_injection and indirect_prompt_injection
    bad.stdout.fnmatch_lines(["*AgentSec:*finding(s)*", "*CRITICAL*"])


def test_plugin_missing_policy_is_a_clear_failure(pytester, monkeypatch):
    pytester.makepyfile(test_inner="def test_x(agentsec_run): pass")
    res = _run_inner(pytester, monkeypatch, ("--agentsec-policy", "nope.yaml"))
    res.assert_outcomes(errors=1)
    res.stdout.fnmatch_lines(["*could not be loaded*"])
