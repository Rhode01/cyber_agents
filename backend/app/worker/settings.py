"""arq worker entrypoint.

Run with:

    poetry run arq app.worker.settings.WorkerSettings

Liveness is checked with ``arq --check app.worker.settings.WorkerSettings``,
which is what the compose healthcheck uses.
"""

from __future__ import annotations

from collections.abc import Callable, Coroutine
from typing import Any, ClassVar

from arq.connections import RedisSettings
from arq.cron import CronJob

from app.core.config import get_settings
from app.core.logging import configure_logging, get_logger
from app.db.session import dispose_engine
from app.worker.tasks import agent_run, analyze_scan, ping

logger = get_logger(__name__)


async def startup(ctx: dict[str, Any]) -> None:
    """Configure logging before the first job runs."""
    configure_logging()
    logger.info("worker.startup", redis_url=get_settings().redis_url)


async def shutdown(ctx: dict[str, Any]) -> None:
    """Release pooled database connections."""
    await dispose_engine()
    logger.info("worker.shutdown")


class WorkerSettings:
    """arq configuration. Scheduled jobs are deferred to a later phase."""

    functions: ClassVar[list[Callable[..., Coroutine[Any, Any, Any]]]] = [
        ping,
        agent_run,
        analyze_scan,
    ]
    cron_jobs: ClassVar[list[CronJob]] = []
    redis_settings: RedisSettings = RedisSettings.from_dsn(get_settings().redis_url)
    on_startup = startup
    on_shutdown = shutdown
    max_jobs = 10
    job_timeout = 300
    health_check_interval = 10
    keep_result = 3600
