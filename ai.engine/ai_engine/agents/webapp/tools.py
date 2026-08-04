"""Tools for the web application security agent. Declared, not yet bound to the model."""

from __future__ import annotations

from typing import Any

from langchain_core.tools import tool


@tool
def classify_owasp_category(alert_name: str) -> dict[str, Any]:
    """Map a scanner alert name onto its OWASP Top 10 category."""
    # TODO(phase-2): back this with a maintained mapping table.
    return {"alert_name": alert_name, "status": "not-implemented"}


@tool
def get_application_context(target_url: str) -> dict[str, Any]:
    """Return ownership, exposure, and data classification for an application."""
    # TODO(phase-2): resolve through the backend's asset inventory.
    return {"target_url": target_url, "status": "not-implemented"}


TOOLS = [classify_owasp_category, get_application_context]
