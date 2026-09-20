"""pytest integration. Installed automatically (entry point `pytest11`).

    # tests/test_agent_security.py
    import pytest
    from agentsec import CATEGORIES

    @pytest.mark.parametrize("category", CATEGORIES)
    def test_agent_resists(category, agentsec_run):
        agentsec_run(category, fail_on="high")

Run with:  pytest --agentsec-policy agentsec.yaml [--agentsec-seed 0]
"""
from __future__ import annotations

import pytest

from .api import AgentTarget, RunResult, SecuritySuite
from .policies import PolicyError, load_policy


def pytest_addoption(parser):
    group = parser.getgroup("agentsec", "Invaris AgentSec")
    group.addoption("--agentsec-policy", default="agentsec.yaml",
                    help="policy file used by the agentsec fixtures (default: agentsec.yaml)")
    group.addoption("--agentsec-seed", type=int, default=0,
                    help="seed for reproducible scenarios (default: 0)")


def pytest_configure(config):
    config.addinivalue_line("markers", "agentsec: runs adversarial scenarios against a live agent")


@pytest.fixture(scope="session")
def agentsec_policy(request):
    path = request.config.getoption("--agentsec-policy")
    try:
        return load_policy(path)
    except PolicyError as exc:
        pytest.fail("agentsec policy %s could not be loaded: %s" % (path, exc), pytrace=False)


@pytest.fixture(scope="session")
def agentsec_target(agentsec_policy):
    return AgentTarget.from_policy(agentsec_policy)


@pytest.fixture(scope="session")
def agentsec_suite(agentsec_target, request):
    return SecuritySuite(agentsec_target, seed=request.config.getoption("--agentsec-seed"))


@pytest.fixture
def agentsec_run(agentsec_suite):
    """Callable `agentsec_run(*names, fail_on="low")`: run categories or scenario ids and
    fail the test with a readable finding list. Returns the RunResult when clean."""
    def run(*names: str, fail_on: str = "low") -> RunResult:
        result = agentsec_suite.run(*names)
        result.assert_clean(fail_on)
        return result
    return run
