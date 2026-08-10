"""Network discovery endpoint.

Proxies the ai.engine's discovery report. The discovery stage runs on the host
the ai.engine lives on, so the backend adds nothing of its own - the report is
returned verbatim for the frontend to turn into scan targets.

Scope: discovery inspects **the device the ai.engine runs on** - its own
interface addresses plus loopback. It does not sweep the surrounding subnets. The
distinction matters enough that it is stated here as well as at the
implementation (``cyber.ai.engine/app/discovery/tools.py``), because the wrong
version of this sentence has already appeared in three places.
"""

from __future__ import annotations

from cyber_contracts import DiscoveryReport
from fastapi import APIRouter, HTTPException, status

from app.api.deps import AiEngineDep
from app.core.security import CurrentPrincipal
from app.services.ai_engine.client import AiEngineError

router = APIRouter(prefix="/discovery", tags=["discovery"])


@router.post(
    "/run",
    response_model=DiscoveryReport,
    summary="Discover this device's interfaces and the services it exposes",
    responses={status.HTTP_502_BAD_GATEWAY: {"description": "The ai.engine did not answer."}},
)
async def run_discovery(client: AiEngineDep, principal: CurrentPrincipal) -> DiscoveryReport:
    """Enumerate this device's interfaces and probe its own addresses for services."""
    del principal
    try:
        return await client.run_discovery()
    except AiEngineError as err:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(err)) from err
