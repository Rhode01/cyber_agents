"""arq task definitions.

Two real jobs plus a liveness probe:

``analyze_scan``  an uploaded scanner report -> parse -> ai.engine -> findings
``agent_run``     one agent over one artifact, out of band
``ping``          no-op, so the worker can be exercised end to end

Both jobs own a session for their whole lifetime and commit as they go, so a
polling client sees real progress rather than a jump from queued to done. Neither
contains detection logic - that lives in the ai.engine.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from arq import create_pool
from arq.connections import RedisSettings
from cyber_contracts import (
    AgentKind,
    ScanFormat,
    ScanStatus,
    VulnerabilityAnalyzeRequest,
)
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.db.session import get_sessionmaker
from app.models.run import Run
from app.models.scan import Scan
from app.schemas.agents import AgentRunRequest
from app.schemas.run import AgentStatusSnapshot
from app.services.ai_engine.client import AiEngineClient, AiEngineError
from app.services.ingestion import ScanParseError, parse
from app.services.orchestration import persist_findings, run_agent
from app.services.verification import verify_from_scan

logger = get_logger(__name__)


async def ping(ctx: dict[str, Any]) -> str:
    """No-op task. Exists so the worker can be exercised end to end."""
    logger.info("worker.ping", job_id=ctx.get("job_id"))
    return "pong"


async def agent_run(ctx: dict[str, Any], agent: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Run one agent over one artifact out of band, and persist what it returns.

    This is the same call the inline route makes; the only difference is who
    waits. A self-launched nmap or nuclei scan takes minutes, which is too long
    to hold an HTTP request open, so the client polls
    ``GET /findings?run_id=...`` instead.

    Previously this logged "received" and returned ``{"status": "accepted",
    "findings": []}`` without doing anything, so ``background: true`` was a
    request that appeared to succeed and silently analysed nothing.
    """
    job_id = ctx.get("job_id")
    try:
        agent_kind = AgentKind(agent)
        request = AgentRunRequest.model_validate(payload)
    except ValueError as err:
        # A malformed job cannot be retried into correctness, so record why and
        # let it end rather than failing repeatedly.
        logger.error("worker.agent_run.invalid", job_id=job_id, agent=agent, error=str(err))
        return {"agent": agent, "status": "invalid", "error": str(err), "findings": 0}

    logger.info(
        "worker.agent_run.start", job_id=job_id, agent=agent, source=request.source,
    )

    factory = get_sessionmaker()
    client = AiEngineClient()
    try:
        async with factory() as session:
            await _record_agent_status(
                session, request.run_id, agent, AgentStatusSnapshot(state="running")
            )
            rows = await run_agent(session, client, agent_kind, request)
            await _record_agent_status(
                session,
                request.run_id,
                agent,
                AgentStatusSnapshot(state="done", count=len(rows), job_id=job_id),
            )
    except AiEngineError as err:
        # Surfaced through the job result rather than swallowed: arq keeps it, and
        # re-raising would retry a call that already failed after its own retries.
        detail = str(err)
        if err.status_code is not None:
            detail = f"{detail} (upstream status {err.status_code})"
        logger.warning("worker.agent_run.failed", job_id=job_id, agent=agent, error=detail)
        async with factory() as session:
            await _record_agent_status(
                session,
                request.run_id,
                agent,
                AgentStatusSnapshot(state="error", error=detail, job_id=job_id),
            )
        return {"agent": agent, "status": "failed", "error": detail, "findings": 0}
    finally:
        await client.aclose()

    logger.info("worker.agent_run.done", job_id=job_id, agent=agent, findings=len(rows))
    return {"agent": agent, "status": "completed", "findings": len(rows)}


async def _record_agent_status(
    session: AsyncSession, run_id: UUID | None, agent: str, status: AgentStatusSnapshot
) -> None:
    """Write one agent's state onto its run, if the request named one.

    Background runs were previously invisible server-side: only the browser wrote
    ``runs.agent_statuses``, so a queued run that the operator navigated away from
    left no record of having been attempted at all. No migration is needed -
    ``agent_statuses`` is already JSONB.

    Typed as ``AgentStatusSnapshot`` rather than a bare dict because this is the
    second writer of that column and the first is a browser. When they were both
    writing free-form JSON they drifted, and the UI rendered an unknown state with
    an undefined count.
    """
    if run_id is None:
        return

    run = await session.get(Run, run_id)
    if run is None:
        logger.warning("worker.agent_run.run_missing", run_id=str(run_id), agent=agent)
        return

    # Reassigned rather than mutated in place: SQLAlchemy does not track mutations
    # inside a plain JSONB dict, so an in-place update would never be persisted.
    run.agent_statuses = {
        **(run.agent_statuses or {}),
        agent: status.model_dump(mode="json", exclude_none=True),
    }
    await session.commit()


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
            batch = await client.assess_vulnerability(request)
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

        # ---- verify --------------------------------------------------------
        # No second scan: the backend parsed this artifact, so it already holds
        # provable coverage - which hosts were up, and which ports each reported.
        # Re-scanning to verify a scan we just read would be slower and no more
        # truthful.
        verification = await verify_from_scan(
            session, normalized=normalized, batch_findings=stamped, source=f"scan://{scan.id}"
        )

        logger.info(
            "scan.analyze.done",
            scan_id=scan_id,
            findings=len(rows),
            **verification.counts(),
        )
        return {
            "scan_id": scan_id,
            "status": ScanStatus.completed.value,
            "findings": len(rows),
            "verification": verification.counts(),
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
