"""`agentsec upload`: send a report to a hosted AgentSec dashboard.

Opt-in only. Nothing in AgentSec uploads anything unless this command is run. The token is read
from an environment variable (never a command-line argument, which would end up in shell history
and CI logs), and it is only ever sent over HTTPS, or plain HTTP to this machine for local testing.
"""
from __future__ import annotations

import gzip
import ipaddress
import json
import os
import ssl
import urllib.error
import urllib.request
from typing import Any, Dict, Optional
from urllib.parse import urlsplit

from . import __version__
from .dashboard.index import ReportError, load_report_file

DEFAULT_TOKEN_ENV = "AGENTSEC_TOKEN"
SERVER_ENV = "AGENTSEC_SERVER"


class UploadError(Exception):
    """The upload failed. The message is user-facing."""


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """urllib would follow a redirect and re-send the Authorization header to the new location, even
    to another host or from https down to http. A dashboard never redirects uploads, so refuse."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401 - stdlib signature
        raise UploadError("the dashboard answered with a redirect (HTTP %d to %s); not following it with "
                          "the token. Check --server" % (code, newurl))


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def endpoint(server: str) -> str:
    parts = urlsplit(server.strip())
    if parts.scheme not in ("https", "http") or not parts.hostname:
        raise UploadError("--server must be a URL like https://dashboard.example.com, got %r" % server)
    if parts.scheme == "http" and not _is_loopback(parts.hostname):
        raise UploadError("refusing to send the token over plain HTTP to %s; use https://" % parts.hostname)
    return server.rstrip("/") + "/api/v1/reports"


def ci_metadata(env: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """Branch, commit and run link, read from GitHub Actions' own variables when present."""
    env = os.environ if env is None else env
    meta: Dict[str, str] = {}
    if env.get("GITHUB_ACTIONS") == "true":
        meta["branch"] = env.get("GITHUB_HEAD_REF") or env.get("GITHUB_REF_NAME") or ""
        meta["commit"] = env.get("GITHUB_SHA", "")
        if env.get("GITHUB_SERVER_URL") and env.get("GITHUB_REPOSITORY") and env.get("GITHUB_RUN_ID"):
            meta["ci_url"] = "%s/%s/actions/runs/%s" % (env["GITHUB_SERVER_URL"], env["GITHUB_REPOSITORY"],
                                                        env["GITHUB_RUN_ID"])
        meta["repository"] = env.get("GITHUB_REPOSITORY", "")
        meta["event"] = env.get("GITHUB_EVENT_NAME", "")
    return {k: v for k, v in meta.items() if v}


def strip_traces(report: Dict[str, Any]) -> Dict[str, Any]:
    """Drop the event lists of scenario traces (the agent's full transcripts), keeping outcome,
    usage, findings and their evidence."""
    out = dict(report)
    scenarios = []
    for s in report.get("scenarios", []):
        s = dict(s)
        if isinstance(s.get("trace"), dict):
            t = dict(s["trace"])
            t["events"] = []
            t["events_stripped"] = True
            s["trace"] = t
        scenarios.append(s)
    out["scenarios"] = scenarios
    return out


def build_payload(report: Dict[str, Any], metadata: Dict[str, str]) -> bytes:
    body = json.dumps({"report": report, "metadata": metadata}, ensure_ascii=False).encode("utf-8")
    return gzip.compress(body)


def upload(path: str, server: str, token: str, metadata: Optional[Dict[str, str]] = None,
           no_traces: bool = False, timeout: float = 60.0) -> Dict[str, Any]:
    if not token:
        raise UploadError("no token: set %s to a project token from the dashboard" % DEFAULT_TOKEN_ENV)
    url = endpoint(server)
    try:
        report = load_report_file(path)
    except ReportError as exc:
        raise UploadError(str(exc))
    if no_traces:
        report = strip_traces(report)
    data = build_payload(report, metadata or {})
    req = urllib.request.Request(url, data=data, method="POST", headers={
        "Content-Type": "application/json", "Content-Encoding": "gzip",
        "Authorization": "Bearer " + token, "User-Agent": "agentsec/" + __version__,
        "Accept": "application/json",
    })
    opener = urllib.request.build_opener(_NoRedirects(),
                                         urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    try:
        with opener.open(req, timeout=timeout) as res:
            body = res.read()
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = json.loads(exc.read().decode("utf-8")).get("detail", "")
        except (ValueError, AttributeError):
            pass
        if exc.code == 401:
            raise UploadError("the dashboard rejected the token (401); create a new project token and set %s"
                              % DEFAULT_TOKEN_ENV)
        raise UploadError("upload failed: HTTP %d%s" % (exc.code, (": %s" % detail) if detail else ""))
    except (urllib.error.URLError, OSError) as exc:
        raise UploadError("cannot reach %s: %s" % (url, getattr(exc, "reason", exc)))
    try:
        return json.loads(body.decode("utf-8"))
    except ValueError:
        raise UploadError("the dashboard answered with something that is not JSON")
