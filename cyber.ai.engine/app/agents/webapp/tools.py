"""Tools for the web application security agent. Declared, not yet bound to the model."""

from __future__ import annotations

import os
import time
from typing import Any

from langchain_core.tools import tool

from app.agents.common.scanning import duration_seconds, run_command
from app.agents.common.targets import is_local_target

_NUCLEI_TIMEOUT_SECONDS = 180.0

# A curated slice of the official nuclei template set. Running all ~14k
# templates against one URL takes minutes; these subdirectories cover the
# findings an interactive webapp scan should surface (default credentials,
# misconfigurations, exposure / info-disclosure) and finish in seconds.
# Default-login checks are dropped for local targets: flagging "default logins"
# on a local instance is noise.
_NUCLEI_TEMPLATE_SUBDIRS = (
    "http/default-logins",
    "http/misconfiguration",
    "http/exposures",
)
_NUCLEI_TEMPLATE_SUBDIRS_NON_LOCAL_ONLY = "http/default-logins"

# Resolved once at import: the container's HOME is fixed, so the template store
# location cannot change at runtime.
_NUCLEI_TEMPLATES_DIR = os.path.join(os.path.expanduser("~"), "nuclei-templates")
_NUCLEI_AVAILABLE_SUBDIRS = [
    subdir
    for subdir in _NUCLEI_TEMPLATE_SUBDIRS
    if os.path.isdir(os.path.join(_NUCLEI_TEMPLATES_DIR, subdir))
]



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

    subdirs = [
        subdir for subdir in _NUCLEI_AVAILABLE_SUBDIRS
        if not (is_local_target(target_url) and subdir == _NUCLEI_TEMPLATE_SUBDIRS_NON_LOCAL_ONLY)
    ]
    template_paths = [
        os.path.join(_NUCLEI_TEMPLATES_DIR, subdir) for subdir in subdirs
    ]

    command = [
        "nuclei", "-u", target_url,
        "-jsonl", "-silent", "-nc",
        "-c", "150", "-timeout", "8", "-retries", "1",
        "-duc",
    ]
    if template_paths:
        command += ["-templates", ",".join(template_paths)]

    started_at = time.monotonic()
    returncode, stdout, stderr = await run_command(
        command,
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
