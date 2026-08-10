"""Structured logging for the ai.engine."""

from __future__ import annotations

import logging
import sys

import structlog

from ai_engine.core.config import get_settings


def configure_logging() -> None:
    """Configure structlog and route the stdlib logger through it."""
    settings = get_settings()
    level = getattr(logging, settings.log_level)

    logging.basicConfig(format="%(message)s", stream=sys.stdout, level=level)

    shared_processors: list[structlog.typing.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    renderer: structlog.typing.Processor = (
        structlog.dev.ConsoleRenderer()
        if settings.app_env == "local"
        else structlog.processors.JSONRenderer()
    )

    structlog.configure(
        processors=[*shared_processors, renderer],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.WriteLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """Return a bound logger for the given module name."""
    logger: structlog.stdlib.BoundLogger = structlog.get_logger(name)
    return logger
