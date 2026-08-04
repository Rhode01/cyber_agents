"""Pipeline orchestration.

The Phase 1 flow is the whole flow, minus the intelligence:

    artifact -> backend -> ai.engine agent -> Finding objects -> PostgreSQL

Correlation into incidents, deduplication, and threat-intel enrichment are
deferred to a later phase; the seams for them are the two functions below.
"""

from __future__ import annotations

from cyberagents_contracts import AgentKind, FindingCreate
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.models.finding import Finding as FindingModel
from app.schemas.agents import AgentRunRequest
from app.services.ai_engine_client import AiEngineClient

logger = get_logger(__name__)


def to_model(finding: FindingCreate) -> FindingModel:
    """Map the wire contract onto the ORM row.

    ``evidence`` is copied verbatim. It is untrusted data and must never be
    treated as instructions by anything downstream.
    """
    return FindingModel(
        agent=finding.agent.value,
        title=finding.title,
        description=finding.description,
        severity=finding.severity.value,
        confidence=finding.confidence,
        source=finding.source,
        asset=finding.asset,
        evidence=finding.evidence,
        recommendation=finding.recommendation,
        raw_reference=finding.raw_reference,
        detected_at=finding.detected_at,
    )


async def persist_findings(
    session: AsyncSession, findings: list[FindingCreate]
) -> list[FindingModel]:
    """Store findings and return the persisted rows."""
    rows = [to_model(finding) for finding in findings]

    session.add_all(rows)
    await session.commit()
    for row in rows:
        await session.refresh(row)

    logger.info("findings.persisted", count=len(rows))
    return rows


async def run_agent(
    session: AsyncSession,
    client: AiEngineClient,
    agent: AgentKind,
    request: AgentRunRequest,
) -> list[FindingModel]:
    """Call one ai.engine agent and persist whatever it returns.

    TODO(phase-2): deduplicate against recent findings and feed the correlation
    engine before returning.
    """
    logger.info("agent.run.start", agent=agent.value, source=request.source, asset=request.asset)

    batch = await client.analyze(agent, request)

    if not request.persist:
        logger.info("agent.run.done", agent=agent.value, count=len(batch.findings), persisted=False)
        return [to_model(finding) for finding in batch.findings]

    rows = await persist_findings(session, batch.findings)
    logger.info("agent.run.done", agent=agent.value, count=len(rows), persisted=True)
    return rows
