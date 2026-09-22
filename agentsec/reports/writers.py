from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Sequence, Tuple

from ..runners import SuiteResult
from .html_report import render_html
from .json_report import build_report
from .markdown_report import render_markdown
from .sarif_report import render_sarif

FORMATS = ("json", "html", "markdown", "sarif")
_FILES = {"json": "report.json", "html": "report.html", "markdown": "summary.md", "sarif": "results.sarif"}


def write_reports(suite: SuiteResult, out_dir: str,
                  formats: Sequence[str] = ("json", "html")) -> Tuple[Dict[str, Any], List[str]]:
    """Write the requested report files. Returns (report dict, [paths written])."""
    report = build_report(suite)
    os.makedirs(out_dir, exist_ok=True)
    paths: List[str] = []
    for fmt in formats:
        path = os.path.join(out_dir, _FILES[fmt])
        if fmt == "json":
            text = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
        elif fmt == "html":
            text = render_html(report)
        elif fmt == "sarif":
            text = render_sarif(report)
        else:
            text = render_markdown(report)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        paths.append(path)
    return report, paths
