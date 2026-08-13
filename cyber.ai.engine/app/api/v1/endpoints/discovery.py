"""Network discovery endpoints.

``POST /discovery/run`` returns a DiscoveryReport without any input: the stage
runs entirely against the interfaces of the host the ai.engine runs on. The
backend proxies it to the frontend so the Run page can hand the discovered web
hosts to the web-app agents.

Concurrent requests are coalesced onto one run - see ``run`` below.
"""

from __future__ import annotations

import asyncio
import time

from cyber_contracts import DiscoveryReport
from fastapi import APIRouter

from app.core.logging import get_logger
from app.core.security import InternalKeyGuard
from app.discovery.tools import run_discovery

logger = get_logger(__name__)

router = APIRouter(
    prefix="/discovery", tags=["discovery"], dependencies=[InternalKeyGuard]
)

# The scan in flight right now, if any. Discovery is an expensive read of a
# single shared thing - this device - so a second concurrent request has nothing
# to learn that the first will not tell it.
_in_flight: asyncio.Task[DiscoveryReport] | None = None
_in_flight_lock = asyncio.Lock()


async def _discover() -> DiscoveryReport:
    """Run the discovery stage once and stamp its duration."""
    logger.info("discovery.run.start")
    started_at = time.monotonic()
    interfaces, subnets, live_hosts, web_hosts, services, notes = await run_discovery()
    return DiscoveryReport(
        interfaces=interfaces,
        subnets=subnets,
        live_hosts=live_hosts,
        web_hosts=web_hosts,
        services=services,
        duration_seconds=round(time.monotonic() - started_at, 2),
        notes=notes,
    )


@router.post(
    "/run",
    response_model=DiscoveryReport,
    summary="Discover the device's interfaces, live addresses, and active services",
)
async def run() -> DiscoveryReport:
    """Enumerate interfaces, take the device's own addresses, and probe their services.

    Overlapping callers share one scan. Without this, two clients - or one client
    mounted twice, which is what React's development double-render does - launch
    two concurrent ``nmap -sV`` passes over the same addresses, each taking the
    better part of twenty seconds and each slowing the other down. The observable
    symptom was every ``discovery.run.start`` appearing in the log twice.

    The scan is a detached task rather than an awaited call so that a client
    hanging up does not cancel it out from under whoever else is waiting;
    ``shield`` keeps one caller's cancellation from propagating into the shared
    task.
    """
    global _in_flight

    async with _in_flight_lock:
        current = _in_flight
        if current is not None and not current.done():
            task, joined = current, True
        else:
            task, joined = asyncio.create_task(_discover()), False
            _in_flight = task

    if joined:
        logger.info("discovery.run.joined", reason="a scan of this device is already running")

    return await asyncio.shield(task)
