import jsonschema
import pytest
import yaml

from agentsec.policies import PolicyError, parse_policy, policy_json_schema
from agentsec.traces import Trace, trace_json_schema

MIN = "agent: {name: a, endpoint: 'http://x'}\n"


def test_policy_defaults():
    p = parse_policy(MIN)
    assert p.limits.max_steps == 12 and p.limits.max_tool_calls == 10
    assert p.allowed_tools is None and p.forbidden_actions == []


def test_policy_matches_json_schema(policy_text):
    text = policy_text.format(endpoint="http://x/agent")
    jsonschema.validate(yaml.safe_load(text), policy_json_schema())
    assert parse_policy(text).allowed_tools == ["search_documents", "create_draft"]


@pytest.mark.parametrize("text,fragment", [
    ("limits: {}", "`agent` section is required"),
    (MIN + "limitz: {}", "unknown key"),
    (MIN + "limits: {max_steps: 0}", "limits.max_steps"),
    (MIN + "limits: {max_cost_usd: -1}", "limits.max_cost_usd"),
    (MIN + "version: '2'", "unsupported policy version"),
    (MIN + "allowed_tools: send_email", "allowed_tools must be a list"),
    ("agent: {name: a, endpoint: ftp://x}", "must start with http"),
    ("agent: [", "not valid YAML"),
])
def test_policy_errors(text, fragment):
    with pytest.raises(PolicyError) as exc:
        parse_policy(text)
    assert fragment in str(exc.value)


def test_env_secret_resolution(monkeypatch):
    monkeypatch.setenv("DEMO_SECRET", "hunter2-hunter2")
    p = parse_policy(MIN + "secrets: ['env:DEMO_SECRET', 'env:MISSING_ONE', literal-value]")
    assert p.resolved_secrets() == ["hunter2-hunter2", "literal-value"]
    assert "hunter2" not in str(p.to_report_dict())


def test_trace_roundtrip_and_schema():
    t = Trace("s/1")
    t.add("user_message", content="hi")
    t.add("tool_call", tool_name="search", arguments={"q": 1}, tool_call_id="c1")
    t.usage.steps = 1
    d = t.to_dict()
    jsonschema.validate(d, trace_json_schema())
    assert Trace.from_dict(d).to_dict() == d


def test_trace_rejects_unknown_event():
    with pytest.raises(ValueError):
        Trace("s").add("bogus")
