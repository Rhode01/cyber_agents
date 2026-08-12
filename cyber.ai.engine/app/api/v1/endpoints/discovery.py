"""Network discovery endpoints.

``POST /discovery/run`` returns a DiscoveryReport without any input: the stage
runs entirely against the interfaces of the host the ai.engine runs on. The
backend proxies it to the frontend so the Run page can hand the discovered web
hosts to the web-app agents.
"""

from __future__ import annotations

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


@router.post(
    "/run",
    response_model=DiscoveryReport,
    summary="Discover the device's interfaces, live addresses, and active services",
)
async def run() -> DiscoveryReport:
    """Enumerate interfaces, take the device's own addresses, and probe their services."""
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
