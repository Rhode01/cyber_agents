"""Tools for the network traffic analysis agent. Declared, not yet bound to the model."""

from __future__ import annotations

import time
from collections import Counter
from typing import Any

from langchain_core.tools import tool

from app.agents.common.scanning import duration_seconds, run_command

_SNAPSHOT_TIMEOUT_SECONDS = 25.0
_MAX_SNAPSHOT_LINES = 300


@tool
def get_traffic_baseline(asset: str, window: str) -> dict[str, Any]:
    """Return the established traffic baseline for an asset over a time window."""
    # TODO(phase-2): resolve through the backend, which stores the baselines.
    return {"asset": asset, "window": window, "status": "not-implemented"}


@tool
def check_ip_reputation(ip_address: str) -> dict[str, Any]:
    """Return reputation, ASN, and known-C2 status for an IP address."""
    # TODO(phase-2): resolve through the backend's threat-intel integration.
    return {"ip_address": ip_address, "status": "not-implemented"}


TOOLS = [get_traffic_baseline, check_ip_reputation]


# ---------------------------------------------------------------------------
# Self-launched scanning (MVP)
# ---------------------------------------------------------------------------

def _summarize_snapshot(target: str, lines: list[str]) -> dict[str, Any]:
    """Extract MVP metrics from an ``ss`` TCP snapshot.

    The snapshot is taken on the host running the agent, which for the MVP is
    the analyst's network edge / capture host. Metrics cover the PDF's initial
    list: connections per second (approximated from the live set), SYN states,
    top talkers (peers), and top destination ports.
    """
    states: Counter[str] = Counter()
    peer_counts: Counter[str] = Counter()
    dst_port_counts: Counter[str] = Counter()

    for line in lines:
        parts = line.split()
        if len(parts) < 5:
            continue
        state = parts[0]
        states[state] += 1
        if state == "ESTAB":
            peer = parts[4].rsplit(":", 1)[0] if ":" in parts[4] else parts[4]
            peer_counts[peer] += 1
        local_port = parts[3].rsplit(":", 1)[-1] if ":" in parts[3] else ""
        if local_port.isdigit():
            dst_port_counts[local_port] += 1

    total = sum(states.values())
    return {
        "connections_total": total,
        "established": states.get("ESTAB", 0),
        "listening": states.get("LISTEN", 0),
        "syn_sent": states.get("SYN-SENT", 0),
        "syn_recv": states.get("SYN-RECV", 0),
        "close_wait": states.get("CLOSE-WAIT", 0),
        "top_talkers": peer_counts.most_common(5),
        "top_local_ports": dst_port_counts.most_common(5),
        "target": target or "(this host)",
    }


async def capture_traffic_snapshot(target: str) -> dict[str, Any]:
    """Take a live TCP connection snapshot via ``ss`` and summarise it.

    Returns a text report with a ``METRICS`` block (machine-parseable) followed
    by the raw ``ss -tan`` output for the LLM to reason over. No root is
    required, so the MVP works on any Linux host.
    """
    target = (target or "").strip()

    started_at = time.monotonic()
    returncode, stdout, stderr = await run_command(
        ["ss", "-tan"],
        timeout_seconds=_SNAPSHOT_TIMEOUT_SECONDS,
        label="ss",
    )
    if returncode != 0:
        return {
            "ok": False,
            "tool": "ss",
            "output": "",
            "error": stderr or f"ss exited with {returncode}",
            "meta": {},
        }

    lines = stdout.splitlines()
    # Drop the header row ("State Recv-Q Send-Q Local Address:Port Peer ...")
    data_lines = [ln for ln in lines[1:] if ln.strip()]
    if target:
        data_lines = [
            ln for ln in data_lines
            if target.lower() in ln.lower()
        ]

    metrics = _summarize_snapshot(target, data_lines)
    captured = data_lines[:_MAX_SNAPSHOT_LINES]

    report_lines = [
        f"Live TCP connection snapshot (target: {metrics['target']})",
        f"Captured at {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}",
    ]
    report_lines += [
        f"METRICS {key}={value}"
        for key, value in metrics.items()
        if key != "target" and isinstance(value, (int, float))
    ]
    report_lines.append(f"METRICS target={metrics['target']}")
    report_lines.append(f"--- raw ss output ({len(data_lines)} lines) ---")
    report_lines += captured

    ok = bool(captured) or returncode == 0
    return {
        "ok": ok,
        "tool": "ss",
        "output": "\n".join(report_lines),
        "error": None if ok else "no TCP connections captured",
        "meta": {
            "returncode": returncode,
            "duration_seconds": duration_seconds(started_at),
            "metrics": metrics,
            "lines": len(captured),
        },
    }
