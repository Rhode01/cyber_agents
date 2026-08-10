"""Health endpoint.

Reports the resolved LLM configuration alongside liveness so a misconfigured
model is visible without reading container logs. The API key is never included.
"""

from __future__ import annotations

from fastapi import APIRouter

from ai_engine import __version__
from ai_engine.core.config import get_settings
from ai_engine.llm.factory import describe_model
from ai_engine.schemas.requests import HealthResponse

router = APIRouter(prefix="/health", tags=["health"])

MOUNTED_AGENTS = ["vulnerability", "phishing", "network", "webapp"]


@router.get("", response_model=HealthResponse, summary="ai.engine liveness")
async def health() -> HealthResponse:
    """Return OK if the process is serving requests."""
    settings = get_settings()
    return HealthResponse(
        version=__version__,
        app_env=settings.app_env,
        agents=MOUNTED_AGENTS,
        llm=describe_model(),
    )
