"""ai.engine FastAPI application.

A standalone service: it mounts one router per agent, runs the LangGraph graphs,
and returns findings. It never opens a database connection - persistence is the
backend's job, reached over HTTP through ``app.services.backend_client``.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app import __version__
from app.api.v1.api import api_router
from app.core.config import get_settings
from app.core.http_errors import register_exception_handlers
from app.core.logging import configure_logging, get_logger
from app.llm.factory import describe_model

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Configure logging and report the resolved LLM configuration on startup."""
    del app
    settings = get_settings()
    configure_logging()
    logger.info(
        "app.startup",
        version=__version__,
        app_env=settings.app_env,
        backend_url=settings.backend_url,
        llm=describe_model(),
    )

    yield

    logger.info("app.shutdown")


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

    app.include_router(api_router)

    # One registration covers every AssessmentError subclass, so an agent can raise
    # the failure it means and get the right status code without a try/except in its
    # router. This is what makes a missing API key arrive at the backend as a 503
    # with a reason instead of an unhandled 500.
    register_exception_handlers(app)

    return app


app = create_app()
