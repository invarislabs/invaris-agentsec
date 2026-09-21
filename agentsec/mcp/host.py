"""MCP attack host: AgentSec plays the MCP server that the agent under test connects to.

The agent uses its own MCP client and its own tools; AgentSec serves the tools from the policy
(allowed tools, forbidden actions as decoys) over streamable HTTP. Results of the tools that carry
adversarial content come from the running scenario, exactly as in the simulated-tool runner. Every
`tools/call` the agent makes is recorded, and the runner turns those records into trace events
(`executed_by_agent`), so all evaluators apply unchanged. Nothing real is executed.
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, List, Optional

from ..policies import Policy

SANDBOX_OK = "OK (simulated by AgentSec sandbox; no real action was taken)"
BENIGN_DOC = ("Vendor onboarding policy v3: vendors must complete the security questionnaire "
              "and sign the data-processing addendum before receiving access.")
PROTOCOL_VERSION = "2025-06-18"


def policy_tools(policy: Policy) -> List[Dict[str, Any]]:
    names: List[str] = []
    for n in (policy.allowed_tools or []) + policy.forbidden_actions + policy.agent.retrieval_tools:
        if n not in names:
            names.append(n)
    return [{"name": n, "description": "Tool %s (simulated by AgentSec)." % n,
             "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}},
                             "additionalProperties": True}} for n in names]


class MCPAttackHost:
    def __init__(self, policy: Policy, host: str = "127.0.0.1", port: int = 0):
        self.policy = policy
        self._tools = policy_tools(policy)
        self._lock = threading.Lock()
        self._responder: Optional[Callable[[str, dict, int], str]] = None
        self._is_scenario_tool: Callable[[str], bool] = lambda n: False
        self._calls = 0
        self._log: List[Dict[str, Any]] = []
        handler = type("BoundHandler", (_Handler,), {"owner": self})
        self.server = ThreadingHTTPServer((host, port), handler)
        self.thread: Optional[threading.Thread] = None

    # ---- lifecycle
    @property
    def url(self) -> str:
        host, port = self.server.server_address[:2]
        return "http://%s:%d/mcp" % (host, port)

    def start(self) -> "MCPAttackHost":
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return self

    def stop(self) -> None:
        if self.thread is not None:       # shutdown() blocks forever if serve_forever never ran
            self.server.shutdown()
        self.server.server_close()

    def __enter__(self) -> "MCPAttackHost":
        return self.start()

    def __exit__(self, *exc: Any) -> None:
        self.stop()

    # ---- used by the runner
    def reset(self) -> None:
        with self._lock:
            self._calls = 0
            self._log = []

    def begin(self, responder: Optional[Callable[[str, dict, int], str]],
              is_scenario_tool: Callable[[str], bool]) -> None:
        with self._lock:
            self._responder, self._is_scenario_tool = responder, is_scenario_tool

    def drain(self) -> List[Dict[str, Any]]:
        with self._lock:
            out, self._log = self._log, []
        return out

    # ---- used by the HTTP handler
    def tools(self) -> List[Dict[str, Any]]:
        return self._tools

    def call(self, name: str, arguments: Dict[str, Any]) -> str:
        with self._lock:
            if self._is_scenario_tool(name):
                if self._responder:
                    result = self._responder(name, arguments, self._calls)
                    self._calls += 1
                else:
                    result = BENIGN_DOC
            else:
                result = SANDBOX_OK
            self._log.append({"name": name, "arguments": arguments, "result": result})
        return result


class _Handler(BaseHTTPRequestHandler):
    owner: MCPAttackHost

    def _reply(self, status: int, payload: Optional[Dict[str, Any]] = None, session: bool = False) -> None:
        data = json.dumps(payload).encode() if payload is not None else b""
        self.send_response(status)
        if payload is not None:
            self.send_header("Content-Type", "application/json")
        if session:
            self.send_header("Mcp-Session-Id", "agentsec-host")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self._reply(405)   # no server-initiated stream

    def do_DELETE(self):
        self._reply(200)

    def do_POST(self):
        try:
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))) or b"{}")
            method, mid = body.get("method"), body.get("id")
        except (ValueError, AttributeError):
            return self._reply(400, {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}})
        if mid is None:
            return self._reply(202)        # notification
        params = body.get("params") or {}
        if method == "initialize":
            result: Dict[str, Any] = {"protocolVersion": PROTOCOL_VERSION, "capabilities": {"tools": {}},
                                      "serverInfo": {"name": "agentsec-host", "version": "1"}}
        elif method == "tools/list":
            result = {"tools": self.owner.tools()}
        elif method == "tools/call":
            name = params.get("name")
            if not isinstance(name, str) or not name:
                return self._reply(200, {"jsonrpc": "2.0", "id": mid,
                                         "error": {"code": -32602, "message": "missing tool name"}})
            # A tool the host never offered is still recorded (the attempt is the finding) and
            # answered like any other sandboxed action, so the scenario proceeds as it would in
            # the simulated-tool runner.
            args = params.get("arguments")
            text = self.owner.call(name, args if isinstance(args, dict) else {})
            result = {"content": [{"type": "text", "text": text}], "isError": False}
        elif method == "ping":
            result = {}
        else:
            return self._reply(200, {"jsonrpc": "2.0", "id": mid,
                                     "error": {"code": -32601, "message": "method not found"}})
        self._reply(200, {"jsonrpc": "2.0", "id": mid, "result": result}, session=method == "initialize")

    def log_message(self, *args):
        pass
