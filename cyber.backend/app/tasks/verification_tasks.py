"""The explicit re-check job.

The automatic path verifies against a scan the backend already parsed
(``scan_tasks.analyze_scan``). This is the other trigger: an operator has fixed
something and wants to know now, without re-running the whole pipeline.

Unlike the automatic path this one *does* need a scan, because nothing recent
covers the target. It asks the ai.engine to re-check exactly the ports of the
findings under verification, which is what makes the resulting coverage provable.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from arq import create_pool
from arq.connections import RedisSettings
from cyber_contracts import VerificationRequest, VerificationTarget

from app.core.logging import get_logger
from app.db.session import get_sessionmaker
from app.models.finding import Finding
from app.services.ai_engine.client import AiEngineClient, AiEngineError
from app.services.verification import (
    OPEN_STATUSES,
    VerificationOutcome,
    apply_verification,
    candidate_id_of,
)

logger = get_logger(__name__)

MAX_FINDINGS_PER_RECHECK = 200
"""A re-check is a focused confirmation, not a bulk sweep."""


def _targets(findings: list[Finding]) -> list[VerificationTarget]:
    """Group findings into one target per host, carrying their ports.

    Ports come from the findings themselves. Scanning exactly what is being
    verified is the difference between provable coverage and an assumption.
    """
    ports_by_host: dict[str, set[int]] = {}
    for finding in findings:
        if not finding.asset or finding.port is None:
            continue
        ports_by_host.setdefault(finding.asset, set()).add(finding.port)

    return [
        VerificationTarget(host=host, ports=sorted(ports))
        for host, ports in sorted(ports_by_host.items())
    ]


async def recheck_findings(ctx: dict[str, Any], finding_ids: list[str]) -> dict[str, Any]:
    """Re-scan the hosts behind these findings and record what it proved."""
    job_id = ctx.get("job_id")
    ids = [UUID(value) for value in finding_ids[:MAX_FINDINGS_PER_RECHECK]]
    if not ids:
        return {"status": "empty", "verified": 0}

    factory = get_sessionmaker()
    async with factory() as session:
        # A plain loop, not a comprehension: `await` inside a generator expression
        # builds an async generator, which cannot be iterated synchronously.
        findings: list[Finding] = []
        for finding_id in ids:
            row = await session.get(Finding, finding_id)
            if row is not None and row.status in OPEN_STATUSES and candidate_id_of(row):
                findings.append(row)

        if not findings:
            logger.info("verification.recheck.nothing_open", job_id=job_id, requested=len(ids))
            return {"status": "nothing-to-verify", "verified": 0}

        targets = _targets(findings)
        if not targets:
            # Package and container findings have no port for a network scan to
            # cover. Recorded rather than silently skipped, so the UI can say why.
            outcome = await apply_verification(
                session,
                findings=findings,
                report=_empty_report(),
                source=f"recheck://{job_id}",
            )
            return {"status": "unverifiable", "verified": 0, **outcome.counts()}

        client = AiEngineClient()
        try:
            report = await client.verify_vulnerability(
                VerificationRequest(targets=targets, context={"job_id": str(job_id)})
            )
        except AiEngineError as err:
            # Returned, not raised: arq would retry a call that already failed
            # after its own retries, and the operator needs the reason either way.
            detail = str(err)
            if err.status_code is not None:
                detail = f"{detail} (upstream status {err.status_code})"
            logger.warning("verification.recheck.failed", job_id=job_id, error=detail)
            return {"status": "failed", "error": detail, "verified": 0}
        finally:
            await client.aclose()

        outcome = await apply_verification(
            session, findings=findings, report=report, source=f"recheck://{job_id}"
        )

    logger.info(
        "verification.recheck.done",
        job_id=job_id,
        targets=len(targets),
        conclusive=report.conclusive,
        **outcome.counts(),
    )
    return {
        "status": "completed",
        "conclusive": report.conclusive,
        "verified": len(outcome.outcomes),
        **outcome.counts(),
    }


def _empty_report() -> Any:
    """A report that covered nothing, for findings no scan can reach."""
    from datetime import UTC, datetime

    from cyber_contracts import VerificationReport

    return VerificationReport(
        scanned_at=datetime.now(UTC),
        coverage=[],
        observed_candidate_ids=[],
        notes=["No network target could be derived from these findings."],
    )


async def enqueue_recheck(redis_url: str, finding_ids: list[UUID]) -> str | None:
    """Queue a re-check and return its job id."""
    redis = await create_pool(RedisSettings.from_dsn(redis_url))
    try:
        job = await redis.enqueue_job(
            "recheck_findings", [str(finding_id) for finding_id in finding_ids]
        )
    finally:
        await redis.aclose()

    if job is None:
        logger.warning("verification.enqueue.deduplicated", count=len(finding_ids))
        return None
    return job.job_id


__all__ = ["VerificationOutcome", "enqueue_recheck", "recheck_findings"]
