"""A local, read-only web dashboard over AgentSec report files.

Standard library only. It binds to 127.0.0.1 by default, serves nothing but its own static files and
the reports it found, answers GET and HEAD only, and rejects requests whose Host header is not the
address it is listening on (so a web page you visit cannot read your reports through DNS rebinding).
Reports contain your agent's real responses, so treat the dashboard like the report files themselves.
"""
from __future__ import annotations

import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, unquote, urlsplit

from .. import __version__
from ..attacks import CATEGORIES
from ..evaluators import SEVERITIES
from ..owasp import ASI, FRAMEWORK, REFERENCE_URL
from .index import ReportError, ReportIndex
from .insights import compare_reports, insights

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
LOOPBACK = ("127.0.0.1", "localhost", "::1")

_TYPES = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
          ".css": "text/css; charset=utf-8", ".woff2": "font/woff2", ".svg": "image/svg+xml",
          ".txt": "text/plain; charset=utf-8"}

# The page loads nothing from anywhere else, and renders report text as text, never as markup.
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; "
       "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


def _static_files() -> Dict[str, str]:
    """URL path -> file path, fixed at startup. Nothing outside this map is ever served."""
    files: Dict[str, str] = {}
    for dirpath, _, filenames in os.walk(STATIC_DIR):
        for name in filenames:
            if os.path.splitext(name)[1] not in _TYPES:
                continue
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, STATIC_DIR).replace(os.sep, "/")
            files["/static/" + rel] = full
    files["/"] = os.path.join(STATIC_DIR, "index.html")
    return files


class DashboardServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, index: ReportIndex, host: str = "127.0.0.1", port: int = 8710, quiet: bool = True):
        self.index = index
        self.quiet = quiet
        self.static = _static_files()
        super().__init__((host, port), _Handler)
        self.allowed_hosts = self._allowed_hosts(host)

    def _allowed_hosts(self, host: str) -> Optional[set]:
        """Host header values to accept. None (accept any) only for a wildcard bind, which the
        CLI warns about: such a server is reachable from the network anyway."""
        if host in ("", "0.0.0.0", "::"):
            return None
        port = self.server_address[1]
        names = {host} | (set(LOOPBACK) if host in LOOPBACK else set())
        out = set()
        for n in names:
            bracketed = "[%s]" % n if ":" in n else n
            out.update({n.lower(), bracketed.lower(), ("%s:%d" % (bracketed, port)).lower()})
        return out

    @property
    def url(self) -> str:
        host, port = self.server_address[0], self.server_address[1]
        if host in ("0.0.0.0", "::", ""):
            host = "127.0.0.1"
        return "http://%s:%d/" % ("[%s]" % host if ":" in host else host, port)


class _Handler(BaseHTTPRequestHandler):
    server: DashboardServer
    server_version = "agentsec-dashboard/" + __version__
    sys_version = ""

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: D401 - stdlib signature
        if not self.server.quiet:
            sys.stderr.write("dashboard: %s\n" % (fmt % args))

    # Only reads. Everything else is refused.
    def do_POST(self) -> None:
        self._error(405, "the dashboard is read-only")

    do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_POST

    def do_HEAD(self) -> None:
        self._route(head=True)

    def do_GET(self) -> None:
        self._route(head=False)

    def _route(self, head: bool) -> None:
        host = (self.headers.get("Host") or "").strip().lower()
        allowed = self.server.allowed_hosts
        if allowed is not None and host not in allowed:
            self._error(421, "unexpected Host header %r; open the dashboard at %s" % (host, self.server.url), head)
            return
        parts = urlsplit(self.path)
        path = unquote(parts.path)
        query = parse_qs(parts.query)
        try:
            if path in self.server.static:
                self._file(self.server.static[path], head)
            elif path == "/api/meta":
                self._json(self._meta(), head)
            elif path == "/api/reports":
                self._json(self._reports(), head)
            elif path.startswith("/api/reports/"):
                self._json(self._report(path[len("/api/reports/"):]), head)
            elif path == "/api/compare":
                self._json(self._compare(query), head)
            else:
                self._error(404, "not found", head)
        except _HTTPError as exc:
            self._error(exc.status, exc.message, head)
        except (BrokenPipeError, ConnectionResetError):
            pass

    # --- API ---------------------------------------------------------------------------------------
    def _meta(self) -> Dict[str, Any]:
        return {
            "version": __version__,
            "roots": [os.path.abspath(r) for r in self.server.index.roots],
            "cwd": os.getcwd(),
            "severities": list(SEVERITIES),
            "categories": list(CATEGORIES),
            "owasp": {"name": FRAMEWORK, "url": REFERENCE_URL, "categories": ASI},
        }

    def _reports(self) -> Dict[str, Any]:
        entries = self.server.index.scan()
        return {"fingerprint": self.server.index.fingerprint(), "reports": [e.to_dict() for e in entries]}

    def _load(self, report_id: str) -> Tuple[Any, Dict[str, Any]]:
        try:
            return self.server.index.load(report_id)
        except KeyError:
            raise _HTTPError(404, "no report with id %r; it may have been moved or deleted" % report_id)
        except ReportError as exc:
            raise _HTTPError(422, str(exc))

    def _report(self, report_id: str) -> Dict[str, Any]:
        entry, report = self._load(report_id)
        return {"entry": entry.to_dict(), "report": report, "insights": insights(report)}

    def _compare(self, query: Dict[str, List[str]]) -> Dict[str, Any]:
        base_id = (query.get("base") or [""])[0]
        head_id = (query.get("head") or [""])[0]
        if not base_id or not head_id:
            raise _HTTPError(400, "pass both base and head report ids")
        base_entry, base = self._load(base_id)
        head_entry, head = self._load(head_id)
        if base_entry.meta.get("kind") != head_entry.meta.get("kind"):
            raise _HTTPError(422, "cannot compare an MCP scan with an agent test run")
        result = compare_reports(base, head)
        result["base"] = base_entry.to_dict()
        result["head"] = head_entry.to_dict()
        return result

    # --- responses ---------------------------------------------------------------------------------
    def _headers(self, status: int, ctype: str, length: int, cache: str = "no-store") -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", cache)
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.end_headers()

    def _file(self, full: str, head: bool) -> None:
        try:
            with open(full, "rb") as fh:
                body = fh.read()
        except OSError:
            raise _HTTPError(404, "not found")
        ctype = _TYPES.get(os.path.splitext(full)[1], "application/octet-stream")
        cache = "public, max-age=86400" if full.endswith(".woff2") else "no-cache"
        self._headers(200, ctype, len(body), cache)
        if not head:
            self.wfile.write(body)

    def _json(self, data: Any, head: bool) -> None:
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self._headers(200, "application/json; charset=utf-8", len(body))
        if not head:
            self.wfile.write(body)

    def _error(self, status: int, message: str, head: bool = False) -> None:
        body = json.dumps({"error": message}).encode("utf-8")
        self._headers(status, "application/json; charset=utf-8", len(body))
        if not head:
            self.wfile.write(body)


class _HTTPError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def make_server(roots: List[str], host: str = "127.0.0.1", port: int = 8710, quiet: bool = True,
                max_depth: Optional[int] = None) -> DashboardServer:
    index = ReportIndex(list(roots)) if max_depth is None else ReportIndex(list(roots), max_depth=max_depth)
    index.scan()
    return DashboardServer(index, host, port, quiet)


def serve_in_thread(server: DashboardServer) -> threading.Thread:
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return thread
