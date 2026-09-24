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
    assert p.spend_limits is None and p.address_allowlist is None


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


def test_attack_packs_matches_json_schema(policy_text):
    text = policy_text.format(endpoint="http://x/agent") + "attack_packs: [my_pack.py, installed_pack]\n"
    jsonschema.validate(yaml.safe_load(text), policy_json_schema())
    assert parse_policy(text).attack_packs == ["my_pack.py", "installed_pack"]


def test_env_secret_resolution(monkeypatch):
    monkeypatch.setenv("DEMO_SECRET", "hunter2-hunter2")
    p = parse_policy(MIN + "secrets: ['env:DEMO_SECRET', 'env:MISSING_ONE', literal-value]")
    assert p.resolved_secrets() == ["hunter2-hunter2", "literal-value"]
    assert "hunter2" not in str(p.to_report_dict())


SPEND_AND_ALLOWLIST = MIN + """
spend_limits:
  tools: [send_transaction]
  max_transaction: 1000
  max_total: 5000
address_allowlist:
  tools: [send_transaction]
  addresses: ["0xGOOD1", "0xGOOD2"]
"""


def test_spend_limits_and_address_allowlist_parse_and_match_json_schema():
    jsonschema.validate(yaml.safe_load(SPEND_AND_ALLOWLIST), policy_json_schema())
    p = parse_policy(SPEND_AND_ALLOWLIST)
    sl = p.spend_limits
    assert (sl.tools, sl.amount_field, sl.max_transaction, sl.max_total, sl.currency) == (
        ["send_transaction"], "amount", 1000.0, 5000.0, "USD")
    al = p.address_allowlist
    assert (al.tools, al.address_field, al.addresses, al.case_sensitive) == (
        ["send_transaction"], "to", ["0xGOOD1", "0xGOOD2"], False)


def test_spend_limits_and_address_allowlist_custom_fields_and_currency():
    text = MIN + """
spend_limits: {tools: [pay], amount_field: total, max_transaction: 500, currency: EUR}
address_allowlist: {tools: [pay], address_field: iban, addresses: [DE00], case_sensitive: true}
"""
    p = parse_policy(text)
    assert p.spend_limits.amount_field == "total" and p.spend_limits.currency == "EUR"
    assert p.address_allowlist.address_field == "iban" and p.address_allowlist.case_sensitive is True


def test_spend_limits_and_address_allowlist_not_reported_verbatim():
    """Consistent with `secrets_count` for `secrets`: the allowlist's own address values are
    summarized (a count), not echoed whole, so a long or sensitive list doesn't bloat the report."""
    p = parse_policy(SPEND_AND_ALLOWLIST)
    d = p.to_report_dict()
    assert d["spend_limits"] == {"tools": ["send_transaction"], "amount_field": "amount",
                                 "max_transaction": 1000.0, "max_total": 5000.0, "currency": "USD"}
    assert d["address_allowlist"] == {"tools": ["send_transaction"], "address_field": "to",
                                      "addresses_count": 2, "case_sensitive": False}


def test_policy_without_spend_limits_or_address_allowlist_reports_none():
    assert parse_policy(MIN).to_report_dict()["spend_limits"] is None
    assert parse_policy(MIN).to_report_dict()["address_allowlist"] is None


@pytest.mark.parametrize("text,fragment", [
    (MIN + "spend_limits: {}", "spend_limits.tools must name at least one tool"),
    (MIN + "spend_limits: {tools: []}", "spend_limits.tools must name at least one tool"),
    (MIN + "spend_limits: {tools: [pay]}", "spend_limits must set max_transaction and/or max_total"),
    (MIN + "spend_limits: {tools: [pay], max_transaction: -1}", "spend_limits.max_transaction"),
    (MIN + "spend_limits: {tools: [pay], max_transaction: 1, bogus: 1}", "unknown key"),
    (MIN + "spend_limits: {tools: [pay], max_transaction: 1, amount_field: ''}", "must be a non-empty string"),
    (MIN + "address_allowlist: {}", "address_allowlist.tools must name at least one tool"),
    (MIN + "address_allowlist: {tools: [pay]}", "address_allowlist.addresses must list at least one address"),
    (MIN + "address_allowlist: {tools: [], addresses: [a]}", "address_allowlist.tools must name at least one tool"),
    (MIN + "address_allowlist: {tools: [pay], addresses: [a], case_sensitive: nope}", "case_sensitive"),
    (MIN + "address_allowlist: {tools: [pay], addresses: [a], bogus: 1}", "unknown key"),
])
def test_spend_limits_and_address_allowlist_errors(text, fragment):
    with pytest.raises(PolicyError) as exc:
        parse_policy(text)
    assert fragment in str(exc.value)


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
