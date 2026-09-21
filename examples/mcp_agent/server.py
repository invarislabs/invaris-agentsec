#!/usr/bin/env python3
"""Reference agent that uses its tools through MCP, for testing `agentsec test --mcp-listen`.

It exposes the usual OpenAI-compatible chat endpoint, but it declares no tools of its own: it
connects to an MCP server (AgentSec's attack host), lists the tools there and calls them itself,
reusing the decision logic of examples/vulnerable_rag_agent.

  python examples/mcp_agent/server.py --mcp-url http://127.0.0.1:8765/mcp            # vulnerable
  python examples/mcp_agent/server.py --mcp-url http://127.0.0.1:8765/mcp --safe     # hardened

DO NOT deploy this. The vulnerable mode obeys any instruction it sees, on purpose.
"""
import argparse
import importlib.util
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from agentsec.mcp import MCPError, connect_http  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "vulnerable_rag_agent_server", ROOT / "examples" / "vulnerable_rag_agent" / "server.py")
brain = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(brain)

MAX_STEPS = 60


def run_agent(question_messages, mcp_url, safe, memory, session):
    """The agent loop: decide, call MCP tools, feed results back, until it answers."""
    with connect_http(mcp_url) as mcp:
        mcp.initialize()
        tool_names = [t["name"] for t in mcp.list_tools()]
        messages = list(question_messages)
        for _ in range(MAX_STEPS):
            reply = brain.respond(messages, tool_names, safe, memory, session)
            calls = reply.get("tool_calls") or []
            if not calls:
                return reply["content"] or ""
            messages.append({"role": "assistant", "content": reply.get("content"), "tool_calls": calls})
            for c in calls:
                args = json.loads(c["function"]["arguments"])
                result = mcp.call_tool(c["function"]["name"], args)
                messages.append({"role": "tool", "tool_call_id": c["id"], "content": result})
        return "Stopped after too many steps."


class Handler(BaseHTTPRequestHandler):
    mcp_url = ""
    safe = False
    memory = None

    def do_POST(self):
        try:
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))) or b"{}")
            session = str(body.get("user") or self.headers.get("X-AgentSec-Session") or "default")
            text = run_agent(body["messages"], self.mcp_url, self.safe, self.memory, session)
        except (KeyError, ValueError) as exc:
            return self._send(400, {"error": "bad request: %s" % exc})
        except MCPError as exc:
            return self._send(502, {"error": "MCP server problem: %s" % exc})
        self._send(200, {"id": "chatcmpl-mcp", "object": "chat.completion", "model": body.get("model", "mcp"),
                         "choices": [{"index": 0, "message": {"role": "assistant", "content": text},
                                      "finish_reason": "stop"}],
                         "usage": {"prompt_tokens": 10, "completion_tokens": max(1, len(text) // 4)}})

    def _send(self, status, payload):
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


def make_server(mcp_url, port=8200, safe=False, host="127.0.0.1"):
    handler = type("BoundHandler", (Handler,), {"mcp_url": mcp_url, "safe": safe, "memory": brain.Memory()})
    return ThreadingHTTPServer((host, port), handler)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--mcp-url", required=True, help="the MCP server this agent uses (AgentSec's --mcp-listen URL)")
    ap.add_argument("--port", type=int, default=8200)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--safe", action="store_true")
    args = ap.parse_args()
    server = make_server(args.mcp_url, args.port, args.safe, args.host)
    print("%s MCP-connected agent on http://%s:%d/agent (MCP: %s)"
          % ("SAFE" if args.safe else "VULNERABLE", args.host, args.port, args.mcp_url))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
