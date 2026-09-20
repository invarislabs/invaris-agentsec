import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from agentsec.adapters import AdapterError, AgentAdapter, AgentReply, HTTPAgentAdapter, ToolCall
from agentsec.attacks.base import Scenario
from agentsec.policies import parse_policy
from agentsec.runners import run_scenario

POLICY = """
agent: {name: a, endpoint: 'http://x'}
allowed_tools: [search_documents]
forbidden_actions: [send_email]
limits: {max_steps: 4, max_tool_calls: 3}
"""


class Scripted(AgentAdapter):
    def __init__(self, replies):
        self.replies, self.calls = list(replies), []

    def chat(self, messages, tools):
        self.calls.append((list(messages), tools))
        return self.replies.pop(0)


def call(name="search_documents", **args):
    return AgentReply(tool_calls=[ToolCall("c", name, args)])


def sc(**kw):
    return Scenario(id="t/1", category="t", title="t", description="t", user_message="hello", **kw)


def test_completes_without_tools():
    tr = run_scenario(sc(), parse_policy(POLICY), Scripted([AgentReply(content="hi")]))
    assert tr.outcome == "completed" and tr.usage.steps == 1
    assert [e.type for e in tr.events] == ["user_message", "assistant_message"]


def test_tool_results_flow_back_and_declared_tools_include_decoys():
    ad = Scripted([call(q=1), AgentReply(content="done")])
    run_scenario(sc(responder=lambda t, a, i: "POISON"), parse_policy(POLICY), ad)
    msgs, tools = ad.calls[1]
    assert msgs[-1] == {"role": "tool", "tool_call_id": "c", "content": "POISON"}
    assert {t["function"]["name"] for t in tools} == {"search_documents", "send_email"}


def test_forbidden_tool_gets_sandbox_result_not_payload():
    ad = Scripted([call("send_email"), AgentReply(content="ok")])
    run_scenario(sc(responder=lambda t, a, i: "POISON"), parse_policy(POLICY), ad)
    assert "simulated" in ad.calls[1][0][-1]["content"]


def test_tool_call_budget_stops_run():
    ad = Scripted([call(q=i) for i in range(10)])
    tr = run_scenario(sc(), parse_policy(POLICY), ad)
    assert tr.outcome == "limit_exceeded" and tr.limit == "max_tool_calls"
    assert len(tr.of_type("tool_call")) == 4 and tr.of_type("tool_call")[-1].meta["over_budget"]


def test_step_limit_stops_run():
    p = parse_policy(POLICY.replace("max_tool_calls: 3", "max_tool_calls: 50"))
    tr = run_scenario(sc(), p, Scripted([call(q=i) for i in range(10)]))
    assert tr.limit == "max_steps" and tr.usage.steps == 4


def test_time_limit_uses_clock():
    p = parse_policy(POLICY + "")
    p.limits.max_seconds = 5
    ticks = iter(range(0, 1000, 10))
    tr = run_scenario(sc(), p, Scripted([call(q=i) for i in range(10)]), clock=lambda: next(ticks))
    assert tr.limit == "max_seconds"


def test_adapter_error_becomes_error_outcome():
    class Boom(AgentAdapter):
        def chat(self, m, t):
            raise AdapterError("down")
    tr = run_scenario(sc(), parse_policy(POLICY), Boom())
    assert tr.outcome == "error" and tr.error == "down"


def test_pricing_computes_cost():
    p = parse_policy(POLICY.replace("agent: {name: a, endpoint: 'http://x'}",
        "agent: {name: a, endpoint: 'http://x', pricing: {input_per_1k: 1.0, output_per_1k: 2.0}}"))
    tr = run_scenario(sc(), p, Scripted([AgentReply(content="x", prompt_tokens=1000, completion_tokens=500)]))
    assert tr.usage.cost_usd == pytest.approx(2.0) and tr.usage.total_tokens == 1500


def test_server_side_executed_calls_are_recorded():
    ad = Scripted([AgentReply(content="sent", executed=[{"name": "send_email", "arguments": {"to": "x"}, "result": "ok"}])])
    tr = run_scenario(sc(), parse_policy(POLICY), ad)
    call_ev = tr.of_type("tool_call")[0]
    assert call_ev.tool_name == "send_email" and call_ev.meta["executed_by_agent"]


# --- HTTP adapter against a tiny fake server -------------------------------

def _serve(payload, status=200, capture=None):
    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            n = int(self.headers["Content-Length"])
            if capture is not None:
                capture.append((json.loads(self.rfile.read(n)), dict(self.headers)))
            data = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *a):
            pass
    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, "http://127.0.0.1:%d/" % srv.server_address[1]


def adapter(url, extra=""):
    return HTTPAgentAdapter(parse_policy("agent: {name: a, endpoint: '%s'%s}" % (url, extra)).agent)


def test_http_parses_tool_calls_and_usage():
    payload = {"choices": [{"message": {"content": None, "tool_calls": [
        {"id": "1", "type": "function", "function": {"name": "f", "arguments": "{\"a\": 1}"}},
        {"id": "2", "type": "function", "function": {"name": "g", "arguments": "not json"}}]}}],
        "usage": {"prompt_tokens": 3, "completion_tokens": 4}, "x_agentsec": {"cost_usd": 0.25}}
    srv, url = _serve(payload)
    r = adapter(url).chat([{"role": "user", "content": "x"}], [])
    srv.shutdown()
    assert [(t.name, t.arguments) for t in r.tool_calls] == [("f", {"a": 1}), ("g", {"_raw": "not json"})]
    assert (r.prompt_tokens, r.completion_tokens, r.cost_usd) == (3, 4, 0.25)


def test_http_plain_text_agent_and_bearer_auth(monkeypatch):
    seen = []
    srv, url = _serve({"response": "hello"}, capture=seen)
    monkeypatch.setenv("MY_KEY", "abc")
    r = adapter(url, ", api_key_env: MY_KEY, model: m1").chat([{"role": "user", "content": "x"}], [])
    srv.shutdown()
    assert r.content == "hello"
    body, headers = seen[0]
    assert body["model"] == "m1" and headers["Authorization"] == "Bearer abc"


def test_http_errors():
    srv, url = _serve({"error": "no"}, status=500)
    with pytest.raises(AdapterError, match="HTTP 500"):
        adapter(url).chat([], [])
    srv.shutdown()
    srv, url = _serve({"weird": 1})
    with pytest.raises(AdapterError, match="neither"):
        adapter(url).chat([], [])
    srv.shutdown()
    with pytest.raises(AdapterError, match="cannot reach"):
        adapter("http://127.0.0.1:1/").chat([], [])
    with pytest.raises(AdapterError, match="NOPE_KEY"):
        adapter(url, ", api_key_env: NOPE_KEY").chat([], [])
