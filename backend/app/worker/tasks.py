"""arq task definitions.

Phase 1 ships one genuinely no-op task (``ping``) so the worker has something to
prove it is alive, and one thin ``agent_run`` task that shows where long agent
runs will live. Neither contains detection logic.
"""

from __future__ import annotations

from typing import Any

from arq import create_pool
from arq.connections import RedisSettings
from cyberagents_contracts import AgentKind

from app.core.logging import get_logger
from app.schemas.agents import AgentRunRequest

logger = get_logger(__name__)


async def ping(ctx: dict[str, Any]) -> str:
    """No-op task. Exists so the worker can be exercised end to end."""
    logger.info("worker.ping", job_id=ctx.get("job_id"))
    return "pong"


async def agent_run(ctx: dict[str, Any], agent: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Run one agent out of band.

    TODO(phase-2): open a session, build an AiEngineClient, and call
    ``app.services.orchestration.run_agent`` the same way the inline route does.
    Phase 1 only records that the job was picked up.
    """
    logger.info(
        "worker.agent_run.received",
        job_id=ctx.get("job_id"),
        agent=agent,
        source=payload.get("source"),
    )
    return {"agent": agent, "status": "accepted", "findings": []}


async def enqueue_agent_run(
    redis_url: str, agent: AgentKind, request: AgentRunRequest
) -> str | None:
    """Put an agent run on the queue and return its job id."""
    redis = await create_pool(RedisSettings.from_dsn(redis_url))
    try:
        job = await redis.enqueue_job(
            "agent_run", agent.value, request.model_dump(mode="json", exclude={"background"})
        )
    finally:
        await redis.aclose()

    if job is None:
        logger.warning("worker.enqueue.deduplicated", agent=agent.value)
        return None

    logger.info("worker.enqueue.ok", agent=agent.value, job_id=job.job_id)
    return job.job_id
