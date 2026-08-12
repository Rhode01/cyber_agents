"""MCP client surface.

Tool execution lives in ``cyber.mcp.server``; this package is how agents reach it.
"""

from app.mcp.client import (
    ALLOWED_TOOLS,
    ASSET_EXPOSURE_TOOL,
    CVE_LOOKUP_TOOL,
    NMAP_SCAN_TOOL,
    McpTools,
    open_tools,
)

__all__ = [
    "ALLOWED_TOOLS",
    "ASSET_EXPOSURE_TOOL",
    "CVE_LOOKUP_TOOL",
    "NMAP_SCAN_TOOL",
    "McpTools",
    "open_tools",
]
