"""A minimal MCP client that only lists tools (`initialize` and `tools/list`).

It never calls a tool, so scanning a server cannot trigger its side effects.
Transports: stdio (newline-delimited JSON-RPC to a subprocess) and streamable HTTP.
"""
from __future__ import annotations

import json
import queue
import shlex
import subprocess
import threading
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

PROTOCOL_VERSION = "2025-06-18"
MAX_PAGES = 50


class MCPError(RuntimeError):
    """The MCP server could not be reached or broke the protocol."""


class MCPClient:
    """Transport-independent part: subclasses implement `_request` and `_notify`."""

    server_info: Dict[str, Any]

    def __init__(self) -> None:
        self._next_id = 0
        self.server_info = {}

    def _id(self) -> int:
        self._next_id += 1
        return self._next_id

    def _request(self, method: str, params: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        raise NotImplementedError

    def _notify(self, method: str) -> None:
        raise NotImplementedError

    def close(self) -> None:
        pass

    def __enter__(self) -> "MCPClient":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def initialize(self) -> Dict[str, Any]:
        result = self._request("initialize", {
            "protocolVersion": PROTOCOL_VERSION, "capabilities": {},
            "clientInfo": {"name": "invaris-agentsec", "version": "0.3"}})
        self.server_info = result.get("serverInfo") or {}
        self._notify("notifications/initialized")
        return result

    def list_tools(self) -> List[Dict[str, Any]]:
        tools: List[Dict[str, Any]] = []
        cursor: Optional[str] = None
        for _ in range(MAX_PAGES):
            result = self._request("tools/list", {"cursor": cursor} if cursor else {})
            page = result.get("tools")
            if not isinstance(page, list):
                raise MCPError("tools/list returned no `tools` list")
            tools.extend(t for t in page if isinstance(t, dict))
            cursor = result.get("nextCursor")
            if not cursor:
                return tools
        raise MCPError("tools/list did not finish after %d pages" % MAX_PAGES)


def _unwrap(msg: Dict[str, Any]) -> Dict[str, Any]:
    if "error" in msg:
        err = msg["error"]
        raise MCPError("server error: %s" % (err.get("message") if isinstance(err, dict) else err))
    result = msg.get("result")
    if not isinstance(result, dict):
        raise MCPError("response has no result object")
    return result


class StdioClient(MCPClient):
    def __init__(self, command: str, timeout_s: float = 20.0, env: Optional[Dict[str, str]] = None):
        super().__init__()
        self.timeout_s = timeout_s
        try:
            self.proc = subprocess.Popen(
                shlex.split(command), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, env=env)
        except (OSError, ValueError) as exc:
            raise MCPError("cannot start MCP server %r: %s" % (command, exc))
        self._lines: "queue.Queue[Optional[bytes]]" = queue.Queue()
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self) -> None:
        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            self._lines.put(line)
        self._lines.put(None)

    def _send(self, obj: Dict[str, Any]) -> None:
        assert self.proc.stdin is not None
        try:
            self.proc.stdin.write(json.dumps(obj).encode() + b"\n")
            self.proc.stdin.flush()
        except (OSError, ValueError):
            raise MCPError("the MCP server closed its input (did it exit?)")

    def _request(self, method: str, params: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        rid = self._id()
        self._send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}})
        while True:
            try:
                line = self._lines.get(timeout=self.timeout_s)
            except queue.Empty:
                raise MCPError("timed out waiting for %s" % method)
            if line is None:
                raise MCPError("the MCP server exited before answering %s" % method)
            try:
                msg = json.loads(line.decode("utf-8", "replace"))
            except ValueError:
                continue  # stray output on stdout; not a protocol message
            if isinstance(msg, dict) and msg.get("id") == rid and "method" not in msg:
                return _unwrap(msg)
            if isinstance(msg, dict) and "method" in msg and "id" in msg:
                # server-initiated request (sampling, roots, ping): decline politely
                self._send({"jsonrpc": "2.0", "id": msg["id"],
                            "error": {"code": -32601, "message": "not supported by the scanner"}})

    def _notify(self, method: str) -> None:
        self._send({"jsonrpc": "2.0", "method": method})

    def close(self) -> None:
        try:
            if self.proc.stdin:
                self.proc.stdin.close()
            self.proc.terminate()
            self.proc.wait(timeout=3)
        except Exception:
            self.proc.kill()


class HTTPClient(MCPClient):
    def __init__(self, url: str, headers: Optional[Dict[str, str]] = None, timeout_s: float = 20.0):
        super().__init__()
        self.url, self.timeout_s = url, timeout_s
        self.headers = dict(headers or {})
        self.session: Optional[str] = None

    def _post(self, body: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
             "MCP-Protocol-Version": PROTOCOL_VERSION}
        h.update(self.headers)
        if self.session:
            h["Mcp-Session-Id"] = self.session
        req = urllib.request.Request(self.url, data=json.dumps(body).encode(), headers=h, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                self.session = resp.headers.get("Mcp-Session-Id") or self.session
                ctype = resp.headers.get("Content-Type", "")
                if "id" not in body:
                    return None
                if "text/event-stream" in ctype:
                    for raw in resp:
                        line = raw.decode("utf-8", "replace").strip()
                        if line.startswith("data:"):
                            try:
                                msg = json.loads(line[5:].strip())
                            except ValueError:
                                continue
                            if isinstance(msg, dict) and msg.get("id") == body["id"]:
                                return msg
                    raise MCPError("the event stream ended without a response")
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise MCPError("server returned HTTP %s" % exc.code)
        except urllib.error.URLError as exc:
            raise MCPError("cannot reach %s: %s" % (self.url, exc.reason))
        except (OSError, ValueError) as exc:
            raise MCPError("request failed: %s" % exc)

    def _request(self, method: str, params: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        msg = self._post({"jsonrpc": "2.0", "id": self._id(), "method": method, "params": params or {}})
        if not isinstance(msg, dict):
            raise MCPError("response is not a JSON object")
        return _unwrap(msg)

    def _notify(self, method: str) -> None:
        self._post({"jsonrpc": "2.0", "method": method})


def connect_stdio(command: str, timeout_s: float = 20.0) -> MCPClient:
    return StdioClient(command, timeout_s)


def connect_http(url: str, headers: Optional[Dict[str, str]] = None, timeout_s: float = 20.0) -> MCPClient:
    if not url.startswith(("http://", "https://")):
        raise MCPError("URL must start with http:// or https://")
    return HTTPClient(url, headers, timeout_s)
