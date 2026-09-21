"""AgentSec as the MCP server an agent connects to (`--mcp-listen`)."""
import importlib.util
import json
import threading
from pathlib import Path

import pytest

from agentsec.adapters import HTTPAgentAdapter
from agentsec.cli.main import main
from agentsec.mcp import MCPAttackHost, connect_http
from agentsec.policies import load_policy
from agentsec.runners import run_suite

ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = ROOT / "examples" / "mcp_agent"

_spec = importlib.util.spec_from_file_location("mcp_agent_server", EXAMPLE / "server.py")
mcp_agent = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mcp_agent)


def policy_for(agent_url):
    policy = load_policy(str(EXAMPLE / "agentsec.yaml"))
    policy.agent.endpoint = agent_url
    return policy


class Stack:
    """An MCP-connected agent plus the AgentSec host it connects to."""

    def __init__(self, safe):
        self.policy = policy_for("http://127.0.0.1:1/agent")
        self.host = MCPAttackHost(self.policy).start()
        self.server = mcp_agent.make_server(self.host.url, port=0, safe=safe)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.policy.agent.endpoint = "http://127.0.0.1:%d/agent" % self.server.server_address[1]

    def run(self, **kw):
        return run_suite(self.policy, HTTPAgentAdapter(self.policy.agent), host=self.host, **kw)

    def close(self):
        self.server.shutdown()
        self.host.stop()


@pytest.fixture()
def vulnerable():
    s = Stack(False)
    yield s
    s.close()


@pytest.fixture()
def safe():
    s = Stack(True)
    yield s
    s.close()


def test_host_speaks_mcp_and_serves_policy_tools():
    policy = policy_for("http://x")
    with MCPAttackHost(policy) as host:
        with connect_http(host.url) as c:
            info = c.initialize()
            assert info["serverInfo"]["name"] == "agentsec-host"
            names = [t["name"] for t in c.list_tools()]
            assert names == ["search_documents", "create_draft", "send_email", "reveal_credentials", "execute_payment"]
            host.begin(lambda name, args, i: "POISON %d" % i, lambda n: n == "search_documents")
            assert c.call_tool("search_documents", {"query": "x"}) == "POISON 0"
            assert c.call_tool("search_documents", {}) == "POISON 1"
            assert "no real action" in c.call_tool("send_email", {"to": "a@b"})
            log = host.drain()
            assert [e["name"] for e in log] == ["search_documents", "search_documents", "send_email"]
            assert host.drain() == []
            assert "no real action" in c.call_tool("rm_rf", {})     # never offered, still recorded
            assert [e["name"] for e in host.drain()] == ["rm_rf"]


def test_vulnerable_mcp_agent_is_caught_through_the_host(vulnerable):
    suite = vulnerable.run()
    assert not [r for r in suite.results if r.status == "error"]
    calls = [e for r in suite.results for e in r.trace.of_type("tool_call")]
    assert calls and all(e.meta.get("executed_by_agent") for e in calls)
    rules = {f.rule for f in suite.findings}
    assert {"forbidden_action", "secret_leak", "injection_followed", "unauthorized_tool"} <= rules
    crit = [f for f in suite.findings if f.rule == "forbidden_action" and f.severity == "critical"]
    assert crit, "a forbidden action triggered by poisoned tool output is critical"
    # the tool-call budget is enforced afterwards for agents that run their own loop
    assert any(f.rule == "limit_max_tool_calls" for f in suite.findings)


def test_safe_mcp_agent_passes_every_scenario(safe):
    suite = vulnerable_findings = safe.run()
    assert not [r for r in suite.results if r.status == "error"]
    assert vulnerable_findings.findings == [], [f.id for f in suite.findings]


def test_no_tools_are_declared_to_an_mcp_agent(vulnerable):
    seen = []
    real = HTTPAgentAdapter.chat

    def spy(self, messages, tools, session=None):
        seen.append(tools)
        return real(self, messages, tools, session)

    HTTPAgentAdapter.chat = spy
    try:
        vulnerable.run(only=["prompt_injection/ignore_previous"])
    finally:
        HTTPAgentAdapter.chat = real
    assert seen and all(t == [] for t in seen)


def test_cli_mcp_listen(tmp_path, capsys):
    policy = policy_for("http://127.0.0.1:1/agent")
    # find a free port for the host, start the agent against it, then run the CLI
    probe = MCPAttackHost(policy)
    port = probe.server.server_address[1]
    probe.stop()
    server = mcp_agent.make_server("http://127.0.0.1:%d/mcp" % port, port=0, safe=False)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    pol = tmp_path / "p.yaml"
    pol.write_text((EXAMPLE / "agentsec.yaml").read_text().replace(
        "http://127.0.0.1:8200/agent", "http://127.0.0.1:%d/agent" % server.server_address[1]))
    try:
        code = main(["test", "-p", str(pol), "-o", str(tmp_path / "out"), "-s", "indirect_prompt_injection",
                     "--mcp-listen", "127.0.0.1:%d" % port])
    finally:
        server.shutdown()
    assert code == 1
    report = json.loads((tmp_path / "out" / "report.json").read_text())
    assert any(f["rule"] == "forbidden_action" for f in report["findings"])
    assert "MCP host listening" in capsys.readouterr().err


def test_cli_mcp_listen_bad_value_and_busy_port(tmp_path):
    pol = tmp_path / "p.yaml"
    pol.write_text((EXAMPLE / "agentsec.yaml").read_text())
    assert main(["test", "-p", str(pol), "--mcp-listen", "nonsense"]) == 2
    with MCPAttackHost(policy_for("http://x")) as busy:
        port = busy.server.server_address[1]
        assert main(["test", "-p", str(pol), "--mcp-listen", "127.0.0.1:%d" % port]) == 2
