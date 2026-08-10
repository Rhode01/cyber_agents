"""Health endpoint.

Reports the resolved LLM configuration alongside liveness so a misconfigured
model is visible without reading container logs. The API key is never included.
"""

from __future__ import annotations

from fastapi import APIRouter

from app import __version__
from app.core.config import get_settings
from app.llm.factory import describe_model
from app.schemas.requests import HealthResponse

router = APIRouter(prefix="/health", tags=["health"])


def _mounted_agents() -> list[str]:
    """The agent list, read from the router registry rather than duplicated here.

    Imported lazily because app.api.v1.api imports this module, and a top-level
    import in both directions would be circular.
    """
    from app.api.v1.api import MOUNTED_AGENTS

    return list(MOUNTED_AGENTS)


@router.get("", response_model=HealthResponse, summary="ai.engine liveness")
async def health() -> HealthResponse:
    """Return OK if the process is serving requests."""
    settings = get_settings()
    return HealthResponse(
        version=__version__,
        app_env=settings.app_env,
        agents=_mounted_agents(),
        llm=describe_model(),
    )
