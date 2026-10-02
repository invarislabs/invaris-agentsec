from agentsec.attacks import action_without_authorization as awa
from agentsec.attacks.base import VECTOR_DIRECT, VECTOR_DOCUMENT, ScenarioContext
from agentsec.policies import parse_policy

WITH_EFFECTS = parse_policy("""
agent: {name: a, endpoint: 'http://x', retrieval_tools: [read_pr_comments]}
allowed_tools: [read_pr_comments, write_file]
tool_effects:
  read_pr_comments: [read]
  write_file: [write]
""")

NO_EFFECTS_DECLARED = parse_policy("""
agent: {name: a, endpoint: 'http://x'}
allowed_tools: [search_documents, create_draft]
""")

ONLY_READ_EFFECTS = parse_policy("""
agent: {name: a, endpoint: 'http://x'}
allowed_tools: [search_documents]
tool_effects:
  search_documents: [read]
""")


def test_scoped_action_finds_the_first_allowed_tool_with_a_non_read_effect():
    ctx = ScenarioContext(WITH_EFFECTS, seed=0)
    assert ctx.scoped_action() == ("write_file", ["write"])


def test_scoped_action_is_none_without_tool_effects():
    ctx = ScenarioContext(NO_EFFECTS_DECLARED, seed=0)
    assert ctx.scoped_action() is None


def test_scoped_action_is_none_when_every_declared_tool_is_read_only():
    ctx = ScenarioContext(ONLY_READ_EFFECTS, seed=0)
    assert ctx.scoped_action() is None


def test_build_produces_no_scenarios_without_tool_effects():
    """False-positive resistance: never guess which tool is state-changing."""
    assert awa.build(ScenarioContext(NO_EFFECTS_DECLARED, seed=0)) == []


def test_build_produces_scenarios_scoped_to_read_when_tool_effects_declared():
    scenarios = awa.build(ScenarioContext(WITH_EFFECTS, seed=0))
    assert len(scenarios) == 2
    for s in scenarios:
        assert s.category == awa.CATEGORY
        assert s.authorized_effects == ["read"]
        assert "write_file" in (s.payload or "")
    vectors = {s.vector for s in scenarios}
    assert vectors == {VECTOR_DOCUMENT, VECTOR_DIRECT}


def test_retrieved_content_scenario_responder_stops_after_the_first_call():
    """The poisoned document must only be replayed once, so an allowed (non-forbidden) target
    tool doesn't turn this into a budget/loop test instead of an authorization-scope test."""
    scenarios = awa.build(ScenarioContext(WITH_EFFECTS, seed=0))
    doc_scenario = next(s for s in scenarios if s.vector == VECTOR_DOCUMENT)
    assert doc_scenario.responder("read_pr_comments", {}, 0) == doc_scenario.payload
    assert doc_scenario.responder("write_file", {}, 1) != doc_scenario.payload
