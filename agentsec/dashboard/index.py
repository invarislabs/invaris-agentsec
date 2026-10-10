"""Find AgentSec report files on disk and load them for the dashboard.

The dashboard never runs scenarios. It reads the files `agentsec test`, `agentsec replay` and
`agentsec mcp scan` already write (`report.json`, `mcp-report.json`), so it works on reports from
CI artifacts, teammates and earlier runs exactly as it does on the one you just produced.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

REPORT_FILENAMES = ("report.json", "mcp-report.json")

# Directories that never hold AgentSec reports but can be very large.
_SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv", "env", ".tox", ".nox",
              ".mypy_cache", ".pytest_cache", ".ruff_cache", "site-packages", "dist", "build", ".idea", ".vscode"}

MAX_DEPTH = 6
MAX_REPORT_BYTES = 64 * 1024 * 1024


class ReportError(Exception):
    """A file could not be read as an AgentSec report. The message is user-facing."""


def is_report(data: Any) -> bool:
    """Same shape check as `agentsec compare`: an object with findings and scenarios."""
    return (isinstance(data, dict) and isinstance(data.get("findings"), list)
            and isinstance(data.get("scenarios"), list))


def report_kind(data: Dict[str, Any]) -> str:
    """'mcp_scan' for `agentsec mcp scan`, 'test' for `agentsec test` and `agentsec replay`."""
    return "mcp_scan" if data.get("kind") == "mcp_scan" else "test"


def load_report_file(path: str) -> Dict[str, Any]:
    """Read and shape-check one report file. Raises ReportError with a user-facing message."""
    try:
        if os.path.getsize(path) > MAX_REPORT_BYTES:
            raise ReportError("%s is larger than %d MB" % (path, MAX_REPORT_BYTES // (1024 * 1024)))
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as exc:
        raise ReportError("cannot read %s: %s" % (path, exc))
    if not is_report(data):
        raise ReportError("%s is not an AgentSec report" % path)
    return data


def _report_id(path: str) -> str:
    return hashlib.sha256(os.path.realpath(path).encode("utf-8")).hexdigest()[:12]


def _count(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def summarize_entry(data: Dict[str, Any]) -> Dict[str, Any]:
    """The few fields the run list needs, without findings or traces."""
    run = data.get("run_config") if isinstance(data.get("run_config"), dict) else {}
    summary = data.get("summary") if isinstance(data.get("summary"), dict) else {}
    kind = report_kind(data)
    if kind == "mcp_scan":
        server = run.get("server") if isinstance(run.get("server"), dict) else {}
        name = server.get("name") or run.get("target") or "MCP server"
        target = run.get("target")
    else:
        policy = run.get("policy") if isinstance(run.get("policy"), dict) else {}
        agent = policy.get("agent") if isinstance(policy.get("agent"), dict) else {}
        name = agent.get("name") or "agent"
        target = agent.get("endpoint")
    by_sev = summary.get("by_severity") if isinstance(summary.get("by_severity"), dict) else {}
    return {
        "kind": kind,
        "name": name,
        "target": target,
        "generated_at": data.get("generated_at"),
        "version": (data.get("tool") or {}).get("version"),
        "seed": run.get("seed"),
        "policy_path": run.get("policy_path"),
        "policy_sha256": (run.get("policy") if isinstance(run.get("policy"), dict) else {}).get("source_sha256"),
        "scenarios": summary.get("scenarios", len(data.get("scenarios", []))),
        "passed": summary.get("passed"),
        "with_findings": summary.get("with_findings"),
        "errors": summary.get("errors"),
        "not_observable": summary.get("not_observable"),
        "findings": summary.get("findings", len(data.get("findings", []))),
        "by_severity": {k: _count(by_sev.get(k, 0)) for k in ("critical", "high", "medium", "low")},
    }


@dataclass
class Entry:
    id: str
    path: str
    mtime: float
    size: int
    meta: Dict[str, Any]
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = {"id": self.id, "path": self.path, "display_path": _display(self.path),
             "mtime": self.mtime, "error": self.error}
        d.update(self.meta)
        return d


def _display(path: str) -> str:
    """The path relative to the working directory when it is inside it, otherwise absolute."""
    try:
        rel = os.path.relpath(path)
    except ValueError:      # different drive on Windows
        return path
    return path if rel.startswith("..") else rel


@dataclass
class ReportIndex:
    """Report files under some roots, re-scanned on demand and cached by mtime and size.

    A root may be a directory (searched recursively, skipping virtualenvs, VCS metadata and other
    large trees) or a single report file of any name.
    """
    roots: List[str]
    max_depth: int = MAX_DEPTH
    _entries: Dict[str, Entry] = field(default_factory=dict)
    _cache: Dict[str, Tuple[float, int, Dict[str, Any]]] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def _candidates(self) -> List[str]:
        found: List[str] = []
        for root in self.roots:
            root = os.path.abspath(root)
            if os.path.isfile(root):
                found.append(root)
                continue
            if not os.path.isdir(root):
                continue
            base_depth = root.rstrip(os.sep).count(os.sep)
            for dirpath, dirnames, filenames in os.walk(root):
                depth = dirpath.rstrip(os.sep).count(os.sep) - base_depth
                dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_DIRS
                                     and not d.endswith(".egg-info") and depth < self.max_depth)
                for name in REPORT_FILENAMES:
                    if name in filenames:
                        found.append(os.path.join(dirpath, name))
        seen, unique = set(), []
        for p in found:
            real = os.path.realpath(p)
            if real not in seen:
                seen.add(real)
                unique.append(p)
        return unique

    def scan(self) -> List[Entry]:
        """Re-scan the roots. Unchanged files are not re-read."""
        entries: Dict[str, Entry] = {}
        for path in self._candidates():
            try:
                st = os.stat(path)
            except OSError:
                continue
            rid = _report_id(path)
            cached = self._cache.get(path)
            if cached and cached[0] == st.st_mtime and cached[1] == st.st_size:
                meta = cached[2]
                error = meta.get("_error")
            else:
                try:
                    meta = summarize_entry(load_report_file(path))
                    error = None
                except ReportError as exc:
                    meta, error = {"_error": str(exc)}, str(exc)
                self._cache[path] = (st.st_mtime, st.st_size, meta)
            if error and os.path.basename(path) not in REPORT_FILENAMES:
                continue    # an explicitly listed file that is not a report: skip quietly
            clean = {k: v for k, v in meta.items() if not k.startswith("_")}
            entries[rid] = Entry(rid, os.path.abspath(path), st.st_mtime, st.st_size, clean, error)
        with self._lock:
            self._entries = entries
        return self.entries()

    def entries(self) -> List[Entry]:
        with self._lock:
            items = list(self._entries.values())
        return sorted(items, key=lambda e: (e.meta.get("generated_at") or "", e.mtime), reverse=True)

    def get(self, report_id: str) -> Optional[Entry]:
        with self._lock:
            entry = self._entries.get(report_id)
        if entry is None:
            self.scan()
            with self._lock:
                entry = self._entries.get(report_id)
        return entry

    def load(self, report_id: str) -> Tuple[Entry, Dict[str, Any]]:
        entry = self.get(report_id)
        if entry is None:
            raise KeyError(report_id)
        return entry, load_report_file(entry.path)

    def fingerprint(self) -> str:
        """Changes whenever a report is added, removed or rewritten; the page polls it."""
        h = hashlib.sha256()
        for e in sorted(self.entries(), key=lambda e: e.id):
            h.update(("%s:%s:%s;" % (e.id, e.mtime, e.size)).encode())
        return h.hexdigest()[:16]
