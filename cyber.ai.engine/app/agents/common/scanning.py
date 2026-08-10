"""Helpers for agents that launch their own scans.

The MVP flow is: the analyst provides a target (host, IP, URL, or domain) and
each agent runs the appropriate scanner itself - nmap for hosts, nuclei for web
apps, ``ss`` for a live network snapshot, dig/curl for a phishing URL check -
instead of waiting for pasted tool output.

Scanner output is untrusted data. Every result is stored in the graph state as
``raw_input`` and only reaches a prompt through ``wrap_untrusted``, exactly like
pasted output. Commands are invoked with an argument list (never a shell
string) so a crafted target cannot inject commands.
"""

from __future__ import annotations

import asyncio
import time

from ai_engine.core.logging import get_logger

logger = get_logger(__name__)


async def run_command(
    command: list[str],
    *,
    timeout_seconds: float,
    label: str,
) -> tuple[int, str, str]:
    """Run ``command`` without a shell and return ``(returncode, stdout, stderr)``.

    On timeout the process is killed and a non-zero return code is reported.
    ``FileNotFoundError`` (binary missing) is mapped to a non-zero return code
    with a readable message rather than crashing the graph.
    """
    logger.info("scan.command", tool=label, command=" ".join(command))
    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        return -1, "", f"{label} is not installed on this host"
    except OSError as exc:
        return -1, "", f"failed to run {label}: {exc}"

    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(), timeout=timeout_seconds
        )
    except TimeoutError:
        process.kill()
        await process.wait()
        return -1, "", f"{label} timed out after {timeout_seconds:g}s"

    return process.returncode or 0, stdout.decode(errors="replace"), stderr.decode(errors="replace")


def duration_seconds(started_at: float) -> float:
    """Return elapsed seconds since ``started_at`` (from ``time.monotonic()``)."""
    return round(time.monotonic() - started_at, 2)
