"""ai.engine FastAPI application.

A standalone service: it mounts one router per agent, runs the LangGraph graphs,
and returns findings. It never opens a database connection - persistence is the
backend's job, reached over HTTP through ``ai_engine.clients.backend``.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from ai_engine import __version__
from ai_engine.core.config import get_settings
from ai_engine.core.logging import configure_logging, get_logger
from ai_engine.llm.factory import describe_model
from ai_engine.routers import health, network, phishing, vulnerability, webapp

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Configure logging and report the resolved LLM configuration on startup."""
    del app
    settings = get_settings()
    configure_logging()
    logger.info(
        "ai_engine.startup",
        version=__version__,
        app_env=settings.app_env,
        backend_url=settings.backend_url,
        llm=describe_model(),
    )

    yield

    logger.info("ai_engine.shutdown")


def create_app() -> FastAPI:
    """Build the application and mount every agent router."""
    settings = get_settings()

    app = FastAPI(
        title=settings.app_name,
        version=__version__,
        summary="LangGraph detection agents. One router per agent, no database.",
        lifespan=lifespan,
        docs_url=None if settings.app_env == "production" else "/docs",
        redoc_url=None,
        openapi_url=None if settings.app_env == "production" else "/openapi.json",
    )

    app.include_router(health.router)
    app.include_router(vulnerability.router)
    app.include_router(phishing.router)
    app.include_router(network.router)
    app.include_router(webapp.router)

    return app


app = create_app()
