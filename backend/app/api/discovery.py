"""Network discovery endpoint.

Proxies the ai.engine's discovery report. The discovery stage runs on the host
the ai.engine lives on, so the backend adds nothing of its own - the report is
returned verbatim for the frontend to turn into scan targets.
"""

from __future__ import annotations

from cyberagents_contracts import DiscoveryReport
from fastapi import APIRouter, HTTPException, status

from app.api.deps import AiEngineDep
from app.core.security import CurrentPrincipal
from app.services.ai_engine_client import AiEngineError

router = APIRouter(prefix="/discovery", tags=["discovery"])


@router.post(
    "/run",
    response_model=DiscoveryReport,
    summary="Discover interfaces, live hosts, and web hosts on the local network",
    responses={status.HTTP_502_BAD_GATEWAY: {"description": "The ai.engine did not answer."}},
)
async def run_discovery(client: AiEngineDep, principal: CurrentPrincipal) -> DiscoveryReport:
    """Enumerate interfaces, sweep their subnets, and probe for web services."""
    del principal
    try:
        return await client.run_discovery()
    except AiEngineError as err:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(err)) from err
