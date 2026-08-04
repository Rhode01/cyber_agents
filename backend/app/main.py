"""Backend FastAPI application.

Serves the frontend's API surface, owns persistence, and calls the ai.engine
over HTTP. Nothing here creates a database connection at import time, so the
module can be imported by tests and by Alembic without a live server.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.api.router import api_router
from app.core.config import get_settings
from app.core.logging import configure_logging, get_logger
from app.db.session import dispose_engine

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Configure logging on startup and release the connection pool on shutdown."""
    del app
    settings = get_settings()
    configure_logging()
    logger.info(
        "backend.startup",
        version=__version__,
        app_env=settings.app_env,
        ai_engine_url=settings.ai_engine_url,
    )

    yield

    await dispose_engine()
    logger.info("backend.shutdown")


def create_app() -> FastAPI:
    """Build the application."""
    settings = get_settings()

    app = FastAPI(
        title=settings.app_name,
        version=__version__,
        summary="Ingests security tool output, has the ai.engine interpret it, stores findings.",
        lifespan=lifespan,
        docs_url=None if settings.is_production else "/docs",
        redoc_url=None,
        openapi_url=None if settings.is_production else "/openapi.json",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(api_router)
    return app


app = create_app()
