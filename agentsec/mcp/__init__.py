"""MCP server scanning: connect to an MCP server, list its tools and check the definitions."""
from .checks import scan_tools
from .client import MCPClient, MCPError, connect_http, connect_stdio
from .pin import compare_pins, make_pins
from .report import build_mcp_report, render_mcp_terminal

__all__ = ["MCPClient", "MCPError", "connect_http", "connect_stdio", "scan_tools",
           "make_pins", "compare_pins", "build_mcp_report", "render_mcp_terminal"]
