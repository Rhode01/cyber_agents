"""Pipeline orchestration.

Flow: artifact -> backend -> ai.engine agent -> Finding objects -> PostgreSQL

Deduplication keeps a noisy scanner from writing the same observation twice
within one run or one scan. It is deliberately scoped to that run or scan - see
``app.crud.crud_finding.DedupeKey`` for why suppressing across runs would make a
re-scan look clean.
"""

from __future__ import annotations

from cyber_contracts import AgentKind, FindingCreate
from sqlalchemy.ext.asyncio import AsyncSession

from app import crud
from app.core.logging import get_logger
from app.crud.crud_finding import dedupe_key
from app.models.finding import Finding as FindingModel
from app.schemas.agents import AgentRunRequest
from app.services.ai_engine.client import AiEngineClient

logger = get_logger(__name__)


def to_model(finding: FindingCreate) -> FindingModel:
    """Map the wire contract onto the ORM row.

    ``evidence`` is copied verbatim. It is untrusted data and must never be
    treated as instructions by anything downstream.
    """
    return FindingModel(
        agent=finding.agent.value,
        finding_type=finding.finding_type.value,
        title=finding.title,
        description=finding.description,
        severity=finding.severity.value,
        confidence=finding.confidence,
        source=finding.source,
        asset=finding.asset,
        service=finding.service,
        port=finding.port,
        protocol=finding.protocol,
        cve_ids=list(finding.cve_ids),
        evidence=finding.evidence,
        recommendation=finding.recommendation,
        status=finding.status.value,
        scan_id=finding.scan_id,
        message_id=finding.message_id,
        run_id=finding.run_id,
        raw_reference=finding.raw_reference,
        detected_at=finding.detected_at,
    )


async def persist_findings(
    session: AsyncSession, findings: list[FindingCreate]
) -> list[FindingModel]:
    """Store findings and return the persisted rows, suppressing duplicates.

    Two findings are the same observation when their full
    ``crud_finding.DedupeKey`` matches - agent, asset, port, service, kind, title
    **and** the run or scan that produced them. Including the run means a
    re-scan always records what it saw; excluding port and service (as the
    previous implementation did) collapsed genuinely different findings on the
    same host into one.
    """
    if not findings:
        return []

    seen = await crud.finding.existing_dedupe_keys(session, findings=findings)

    rows: list[FindingModel] = []
    suppressed: list[str] = []

    for candidate in findings:
        key = dedupe_key(candidate)
        if key in seen:
            suppressed.append(candidate.title)
            continue
        rows.append(to_model(candidate))
        # Add as we go so a batch cannot insert the same observation twice.
        seen.add(key)

    if suppressed:
        # Named rather than counted: "3 suppressed" is not actionable, and a
        # surprising title here is how a too-broad dedupe key gets noticed.
        logger.info(
            "findings.deduplicated",
            count=len(suppressed),
            titles=sorted(set(suppressed))[:10],
        )

    if not rows:
        logger.info("findings.persisted", count=0, deduplicated=len(suppressed))
        return []

    persisted = await crud.finding.create_many(session, rows=rows)
    logger.info("findings.persisted", count=len(persisted), deduplicated=len(suppressed))
    return persisted


async def run_agent(
    session: AsyncSession,
    client: AiEngineClient,
    agent: AgentKind,
    request: AgentRunRequest,
) -> list[FindingModel] | list[FindingCreate]:
    """Call one ai.engine agent and persist whatever it returns.

    When ``request.persist`` is false the wire findings are returned as-is (they
    have no id/timestamps yet); otherwise the persisted ORM rows come back.
    """
    logger.info("agent.run.start", agent=agent.value, source=request.source, asset=request.asset)

    # No credentials are injected into the request. The ai.engine resolves its own
    # model and API key from its own environment, so a key never crosses this
    # boundary in a request body and is never stored in the database.
    batch = await client.analyze(agent, request)

    if not request.persist:
        logger.info("agent.run.done", agent=agent.value, count=len(batch.findings), persisted=False)
        return list(batch.findings)

    # Stamp the findings with the run that produced them so the scans page can
    # group them into a per-run session. The ai.engine has no knowledge of runs.
    findings = batch.findings
    if request.run_id is not None:
        findings = [
            finding.model_copy(update={"run_id": request.run_id})
            for finding in findings
        ]

    rows = await persist_findings(session, findings)
    logger.info("agent.run.done", agent=agent.value, count=len(rows), persisted=True)
    return rows
