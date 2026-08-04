"""Health endpoints.

``GET /health`` is process liveness only - no I/O, so it stays useful as a
container healthcheck. ``GET /health/db`` does a real round trip through the
async driver, which is what proves the database wiring actually works.
"""

from __future__ import annotations

import time

from fastapi import APIRouter, Response, status
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app import __version__
from app.api.deps import SessionDep, SettingsDep
from app.core.logging import get_logger
from app.schemas.health import DbHealthResponse, HealthResponse

logger = get_logger(__name__)

router = APIRouter(prefix="/health", tags=["health"])


@router.get("", response_model=HealthResponse, summary="Backend liveness")
async def health(settings: SettingsDep) -> HealthResponse:
    """Return OK if the process is serving requests."""
    return HealthResponse(version=__version__, app_env=settings.app_env)


@router.get(
    "/db",
    response_model=DbHealthResponse,
    summary="PostgreSQL connectivity over asyncpg",
    responses={status.HTTP_503_SERVICE_UNAVAILABLE: {"model": DbHealthResponse}},
)
async def health_db(session: SessionDep, response: Response) -> DbHealthResponse:
    """Execute a trivial query to prove the async connection is live."""
    started = time.perf_counter()
    try:
        result = await session.execute(text("SELECT version()"))
        server_version = str(result.scalar_one())
    except (SQLAlchemyError, OSError) as err:
        # OSError matters: when PostgreSQL is simply not listening, asyncpg
        # raises ConnectionRefusedError before SQLAlchemy can wrap it. A health
        # check must answer 503, never leak a 500 traceback.
        logger.warning("health.db.failed", error=str(err))
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return DbHealthResponse(status="error", error=type(err).__name__)

    elapsed_ms = (time.perf_counter() - started) * 1000
    return DbHealthResponse(
        status="ok",
        latency_ms=round(elapsed_ms, 2),
        server_version=server_version.split(" on ")[0],
    )
