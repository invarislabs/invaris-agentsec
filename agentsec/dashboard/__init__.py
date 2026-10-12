"""`agentsec dashboard`: a local, read-only web view of AgentSec reports.

It reads the `report.json` and `mcp-report.json` files that `agentsec test`, `agentsec replay` and
`agentsec mcp scan` write, and never runs scenarios or contacts an agent itself.
"""
from .index import ReportError, ReportIndex, is_report, report_kind
from .insights import compare_reports, insights
from .server import DashboardServer, make_server, serve_in_thread

__all__ = ["DashboardServer", "ReportError", "ReportIndex", "compare_reports", "insights", "is_report",
           "make_server", "report_kind", "serve_in_thread"]
