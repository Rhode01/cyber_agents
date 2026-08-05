"""Tools for the web application security agent. Declared, not yet bound to the model."""

from __future__ import annotations

import time
from typing import Any

from langchain_core.tools import tool

from ai_engine.agents.common.scanning import duration_seconds, run_command

_NUCLEI_TIMEOUT_SECONDS = 120.0


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


# ---------------------------------------------------------------------------
# Self-launched scanning (MVP)
# ---------------------------------------------------------------------------

async def run_nuclei_scan(target_url: str) -> dict[str, Any]:
    """Run a Nuclei scan against ``target_url`` and return its NDJSON output.

    Launched by the agent itself when no web scanner report is provided. A bare
    hostname is normalised to ``https://`` first. Nuclei emits one JSON object
    per line (``-json``), which the ``nuclei`` parser consumes directly.
    """
    target_url = (target_url or "").strip()
    if not target_url:
        return {
            "ok": False,
            "tool": "nuclei",
            "output": "",
            "error": "Empty target URL",
            "meta": {},
        }

    if not target_url.lower().startswith(("http://", "https://")):
        target_url = f"https://{target_url}"

    started_at = time.monotonic()
    returncode, stdout, stderr = await run_command(
        [
            "nuclei", "-u", target_url,
            "-json", "-silent", "-nc",
            "-timeout", "20", "-retries", "1",
        ],
        timeout_seconds=_NUCLEI_TIMEOUT_SECONDS,
        label="nuclei",
    )
    ok = returncode == 0
    return {
        "ok": ok,
        "tool": "nuclei",
        "output": stdout,
        "error": None if ok else (stderr or f"nuclei exited with {returncode}"),
        "meta": {
            "returncode": returncode,
            "duration_seconds": duration_seconds(started_at),
            "target_url": target_url,
        },
    }
