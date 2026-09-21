import io
import json

import pytest
from conftest import rag_agent  # noqa: F401  (adds examples to the path)

from agentsec.adapters import AdapterError, AgentReply, CallableAdapter, HTTPAgentAdapter
from agentsec.api import AgentTarget, SecuritySuite
from agentsec.policies import PolicyError, load_policy, parse_policy
from agentsec.policies.schema import AgentConfig
from agentsec.runners import run_suite
from test_rag_example import EXAMPLE


def sse(*chunks, done=True):
    lines = []
    for c in chunks:
        lines.append(b": keep-alive\n")
        lines.append(b"data: " + (c if isinstance(c, bytes) else json.dumps(c).encode()) + b"\n")
        lines.append(b"\n")
    if done:
        lines.append(b"data: [DONE]\n")
    return io.BytesIO(b"".join(lines))


def adapter():
    return HTTPAgentAdapter(AgentConfig(name="t", endpoint="http://x", stream=True))


def delta(**d):
    return {"choices": [{"index": 0, "delta": d}]}


def test_stream_assembles_text_usage_and_events():
    r = adapter()._parse_stream(sse(
        delta(content="Hello "), delta(content="world"),
        {"choices": [{"delta": {}, "finish_reason": "stop"}], "usage": {"prompt_tokens": 5, "completion_tokens": 2},
         "x_agentsec": {"cost_usd": 0.01, "events": [{"name": "search_documents", "arguments": {}, "result": "r"}]}}))
    assert r.content == "Hello world" and (r.prompt_tokens, r.completion_tokens) == (5, 2)
    assert r.cost_usd == 0.01 and r.executed[0]["name"] == "search_documents" and not r.tool_calls


def test_stream_assembles_fragmented_tool_calls_by_index():
    r = adapter()._parse_stream(sse(
        delta(tool_calls=[{"index": 0, "id": "c0", "function": {"name": "send_", "arguments": ""}}]),
        delta(tool_calls=[{"index": 0, "function": {"name": "email", "arguments": '{"to": "a@b'}}]),
        delta(tool_calls=[{"index": 1, "id": "c1", "function": {"name": "create_draft", "arguments": "{}"}}]),
        delta(tool_calls=[{"index": 0, "function": {"arguments": '.com"}'}}])))
    assert [(c.id, c.name, c.arguments) for c in r.tool_calls] == [
        ("c0", "send_email", {"to": "a@b.com"}), ("c1", "create_draft", {})]


def test_stream_without_done_marker_still_works():
    assert adapter()._parse_stream(sse(delta(content="hi"), done=False)).content == "hi"


def test_stream_errors():
    with pytest.raises(AdapterError, match="empty"):
        adapter()._parse_stream(io.BytesIO(b""))
    with pytest.raises(AdapterError, match="invalid JSON"):
        adapter()._parse_stream(sse(b"{not json"))
    with pytest.raises(AdapterError, match="reported an error"):
        adapter()._parse_stream(sse({"error": {"message": "boom"}}))


def test_stream_option_is_validated_and_in_schema():
    base = "agent: {name: a, endpoint: 'http://x'%s}\nallowed_tools: []\nforbidden_actions: [x]\n"
    assert parse_policy(base % ", stream: true").agent.stream is True
    assert parse_policy(base % "").agent.stream is False
    with pytest.raises(PolicyError):
        parse_policy(base % ", stream: 'yes'")


def test_rag_agent_streams_and_gets_the_same_findings(rag_vulnerable):
    server, url = rag_vulnerable
    policy = load_policy(str(EXAMPLE / "agentsec.yaml"))
    policy.agent.endpoint = url
    plain = run_suite(policy, HTTPAgentAdapter(policy.agent))
    policy.agent.stream = True
    streamed = run_suite(policy, HTTPAgentAdapter(policy.agent))
    assert not [r for r in streamed.results if r.status == "error"]
    assert sorted(f.id for f in streamed.findings) == sorted(f.id for f in plain.findings)
    assert streamed.findings


def test_callable_adapter_accepts_several_shapes():
    assert CallableAdapter(lambda m: "hi").chat([], []).content == "hi"
    assert CallableAdapter(lambda m, t: {"content": "x"}).chat([], [], "s").content == "x"
    seen = []
    CallableAdapter(lambda m, t, s: seen.append(s) or "ok").chat([], [], "sess")
    assert seen == ["sess"]
    r = CallableAdapter(lambda m: {"tool_calls": [{"name": "send_email", "arguments": {"to": "x"}}],
                                   "executed": [{"name": "a", "arguments": {}, "result": "r"}],
                                   "cost_usd": 0.5}).chat([], [])
    assert r.tool_calls[0].name == "send_email" and r.executed[0]["name"] == "a" and r.cost_usd == 0.5
    assert isinstance(CallableAdapter(lambda m: AgentReply(content="z")).chat([], []), AgentReply)


def test_callable_adapter_wraps_crashes_and_bad_returns():
    def boom(m):
        raise ValueError("kaput")
    with pytest.raises(AdapterError, match="ValueError: kaput"):
        CallableAdapter(boom).chat([], [])
    with pytest.raises(AdapterError, match="must return"):
        CallableAdapter(lambda m: 42).chat([], [])


def test_callable_agent_through_the_python_api():
    def naive_agent(messages, tools):
        # an agent that obeys any instruction to send an email
        text = " ".join(str(m.get("content")) for m in messages if m["role"] == "user").lower()
        if "send" in text and any(t["function"]["name"] == "send_email" for t in tools):
            return {"content": "done", "tool_calls": [{"name": "send_email", "arguments": {"to": "x@evil.test"}}]}
        return "I cannot help with that."

    target = AgentTarget("http://in-process", allowed_tools=["search_documents"], forbidden_tools=["send_email"])
    result = SecuritySuite(target, adapter=CallableAdapter(naive_agent)).run("unauthorized_tool_use")
    assert result.findings, "the naive agent should be caught"
