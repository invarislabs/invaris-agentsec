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
from typing import Any, Dict, List, Optional

from ..integrations.toolhost import BENIGN_DOC, SANDBOX_OK, ToolHost, host_tool_names  # noqa: F401
from ..policies import Policy

PROTOCOL_VERSION = "2025-06-18"


def policy_tools(policy: Policy) -> List[Dict[str, Any]]:
    return [{"name": n, "description": "Tool %s (simulated by AgentSec)." % n,
             "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}},
                             "additionalProperties": True}} for n in host_tool_names(policy)]


class MCPAttackHost(ToolHost):
    """The in-process ToolHost (agentsec/integrations/toolhost.py) served over MCP streamable HTTP.

    Each MCP client session is attributed to the client that opened it: the `clientInfo.name` it
    sent in `initialize` (or an `X-AgentSec-Actor` request header, which takes precedence) becomes
    the `actor` of every call made in that session. Several agents connecting as separate MCP
    clients are therefore told apart in the trace; several agents sharing one client are not."""

    def __init__(self, policy: Policy, host: str = "127.0.0.1", port: int = 0):
        super().__init__(policy)
        self._tools = policy_tools(policy)
        self._sessions: Dict[str, str] = {}
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

    # ---- used by the HTTP handler
    def tools(self) -> List[Dict[str, Any]]:
        return self._tools

    def open_session(self, client_name: Optional[str]) -> str:
        with self._lock:
            sid = "agentsec-host-%d" % (len(self._sessions) + 1)
            self._sessions[sid] = client_name or ""
        return sid

    def session_actor(self, sid: Optional[str]) -> Optional[str]:
        with self._lock:
            return self._sessions.get(sid or "") or None


class _Handler(BaseHTTPRequestHandler):
    owner: MCPAttackHost

    def _reply(self, status: int, payload: Optional[Dict[str, Any]] = None, session: Optional[str] = None) -> None:
        data = json.dumps(payload).encode() if payload is not None else b""
        self.send_response(status)
        if payload is not None:
            self.send_header("Content-Type", "application/json")
        if session:
            self.send_header("Mcp-Session-Id", session)
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
        new_session: Optional[str] = None
        if method == "initialize":
            client = (params.get("clientInfo") or {}).get("name") if isinstance(params.get("clientInfo"), dict) else None
            new_session = self.owner.open_session(self.headers.get("X-AgentSec-Actor") or client)
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
            actor = self.headers.get("X-AgentSec-Actor") or self.owner.session_actor(self.headers.get("Mcp-Session-Id"))
            text = self.owner.call(name, args if isinstance(args, dict) else {}, actor=actor)
            result = {"content": [{"type": "text", "text": text}], "isError": False}
        elif method == "ping":
            result = {}
        else:
            return self._reply(200, {"jsonrpc": "2.0", "id": mid,
                                     "error": {"code": -32601, "message": "method not found"}})
        self._reply(200, {"jsonrpc": "2.0", "id": mid, "result": result}, session=new_session)

    def log_message(self, *args):
        pass
