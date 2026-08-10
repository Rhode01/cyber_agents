"""arq task definitions.

Phase 1 ships one genuinely no-op task (``ping``) so the worker has something to
prove it is alive, and one thin ``agent_run`` task that shows where long agent
runs will live. Neither contains detection logic.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from arq import create_pool
from arq.connections import RedisSettings
from cyberagents_contracts import (
    AgentKind,
    ScanFormat,
    ScanStatus,
    VulnerabilityAnalyzeRequest,
)
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.db.session import get_sessionmaker
from app.ingestion import ScanParseError, parse
from app.models.scan import Scan
from app.schemas.agents import AgentRunRequest
from app.services.ai_engine_client import AiEngineClient, AiEngineError
from app.services.orchestration import persist_findings

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


async def _fail(session: AsyncSession, scan: Scan, reason: str) -> dict[str, Any]:
    """Mark a scan failed with a reason an operator can act on.

    This is the "fail loudly" path. Nothing partial is persisted: the scan is
    retryable, and the frontend renders ``error`` verbatim rather than showing
    findings that were never actually assessed.
    """
    scan.status = ScanStatus.failed.value
    scan.error = reason[:4000]
    await session.commit()
    logger.warning("scan.failed", scan_id=str(scan.id), reason=reason)
    return {"scan_id": str(scan.id), "status": ScanStatus.failed.value, "error": reason}


async def analyze_scan(ctx: dict[str, Any], scan_id: str) -> dict[str, Any]:
    """Parse an uploaded scan, have the ai.engine interpret it, and persist findings.

    Status advances pending -> parsing -> analyzing -> completed, committing at
    each step so the frontend's poll shows real progress rather than jumping from
    pending to done.
    """
    factory = get_sessionmaker()
    async with factory() as session:
        scan = await session.get(Scan, UUID(scan_id))
        if scan is None:
            logger.warning("scan.missing", scan_id=scan_id, job_id=ctx.get("job_id"))
            return {"scan_id": scan_id, "status": "missing"}

        logger.info("scan.analyze.start", scan_id=scan_id, job_id=ctx.get("job_id"))

        if not scan.raw_content:
            return await _fail(session, scan, "The stored scan has no content to parse.")

        # ---- parse ---------------------------------------------------------
        scan.status = ScanStatus.parsing.value
        await session.commit()

        try:
            normalized = parse(scan.raw_content, ScanFormat(scan.format))
        except ScanParseError as err:
            return await _fail(session, scan, f"Could not parse the scan: {err}")

        scan.host_count = normalized.host_count
        scan.status = ScanStatus.analyzing.value
        await session.commit()

        logger.info(
            "scan.parsed",
            scan_id=scan_id,
            hosts=normalized.host_count,
            open_ports=normalized.open_port_count,
        )

        # ---- assess --------------------------------------------------------
        request = VulnerabilityAnalyzeRequest(
            scan_id=scan.id,
            source=normalized.scanner,
            asset=scan.asset,
            scan=normalized,
            context={"filename": scan.filename, "sha256": scan.sha256},
        )

        client = AiEngineClient()
        try:
            batch = await client.analyze_vulnerability(request)
        except AiEngineError as err:
            detail = f"The ai.engine could not assess this scan: {err}"
            if err.status_code is not None:
                detail = f"{detail} (upstream status {err.status_code})"
            return await _fail(session, scan, detail)
        finally:
            await client.aclose()

        # ---- persist -------------------------------------------------------
        stamped = [
            finding.model_copy(
                update={"scan_id": scan.id, "raw_reference": f"scan://{scan.id}"}
            )
            for finding in batch.findings
        ]
        rows = await persist_findings(session, stamped)

        scan.finding_count = len(rows)
        scan.status = ScanStatus.completed.value
        scan.completed_at = datetime.now(UTC)
        scan.error = None
        await session.commit()

        logger.info("scan.analyze.done", scan_id=scan_id, findings=len(rows))
        return {
            "scan_id": scan_id,
            "status": ScanStatus.completed.value,
            "findings": len(rows),
        }


async def enqueue_scan_analysis(redis_url: str, scan_id: UUID) -> str | None:
    """Queue a scan for analysis and return its job id."""
    redis = await create_pool(RedisSettings.from_dsn(redis_url))
    try:
        job = await redis.enqueue_job("analyze_scan", str(scan_id))
    finally:
        await redis.aclose()

    if job is None:
        logger.warning("worker.enqueue.deduplicated", scan_id=str(scan_id))
        return None

    logger.info("worker.enqueue.ok", task="analyze_scan", scan_id=str(scan_id), job_id=job.job_id)
    return job.job_id


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
