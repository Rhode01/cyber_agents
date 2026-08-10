"""Running external scanners.

Ported from ``cyber.ai.engine/app/agents/common/scanning.py`` - the scanners moved
here when tool execution moved behind MCP, and the hardening came with them:

* ``create_subprocess_exec`` with an argv list, never a shell string, so a target
  containing ``; rm -rf /`` is one weird argument rather than two commands;
* a timeout that kills the process rather than leaking it;
* a missing binary reported as an ordinary failed result, because "nmap is not
  installed" is something the caller should read, not an exception trace.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

logger = logging.getLogger("app")


def duration_seconds(started_at: float) -> float:
    """Elapsed wall-clock time, rounded for logging."""
    return round(time.monotonic() - started_at, 3)


async def run_command(
    command: list[str], *, timeout_seconds: float, label: str
) -> tuple[int, str, str]:
    """Run one external command and return ``(returncode, stdout, stderr)``.

    A return code of -1 means the command never produced one: not installed, or
    killed on timeout. Both carry an explanation in stderr.
    """
    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        return -1, "", f"{label} is not installed on this host"
    except OSError as exc:  # permissions, exec format, and similar
        return -1, "", f"{label} could not be started: {exc}"

    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout_seconds)
    except TimeoutError:
        process.kill()
        await process.wait()
        return -1, "", f"{label} exceeded its {timeout_seconds:g}s timeout and was stopped"

    return (
        process.returncode if process.returncode is not None else -1,
        stdout.decode("utf-8", errors="replace"),
        stderr.decode("utf-8", errors="replace"),
    )


def tool_result(
    *,
    ok: bool,
    tool: str,
    output: str = "",
    error: str = "",
    meta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """The one shape every scanner tool returns.

    Failures come back as a result with ``ok: false`` rather than as an MCP
    error, so an agent can reason about "the scan did not run" instead of having
    its tool call blow up.
    """
    return {"ok": ok, "tool": tool, "output": output, "error": error, "meta": meta or {}}
