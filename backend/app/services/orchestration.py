"""Pipeline orchestration.

Flow: artifact -> backend -> ai.engine agent -> Finding objects -> PostgreSQL

Phase 2: Adds basic deduplication against recent findings to prevent noisy
scanners from flooding the database with duplicate alerts.
"""

from __future__ import annotations

import datetime

from cyberagents_contracts import AgentKind, FindingCreate
from sqlalchemy import select
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
        raw_reference=finding.raw_reference,
        detected_at=finding.detected_at,
    )


async def persist_findings(
    session: AsyncSession, findings: list[FindingCreate]
) -> list[FindingModel]:
    """Store findings and return the persisted rows, deduplicating first.
    
    A finding is considered a duplicate if there is an existing finding for the
    same agent, asset, and exact title within the last 24 hours.
    """
    if not findings:
        return []

    # Get recent findings for the same assets
    agents = list({f.agent.value for f in findings})
    assets = list({f.asset for f in findings if f.asset})
    titles = list({f.title for f in findings})
    
    cutoff = datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=1)
    
    # Query for existing matching findings
    stmt = (
        select(FindingModel.agent, FindingModel.asset, FindingModel.title)
        .where(
            FindingModel.agent.in_(agents),
            FindingModel.title.in_(titles),
            FindingModel.detected_at >= cutoff
        )
    )
    if assets:
        stmt = stmt.where(FindingModel.asset.in_(assets))
        
    existing = await session.execute(stmt)
    # Create a set of (agent, asset, title) tuples for O(1) lookup
    existing_set = {tuple(row) for row in existing.all()}

    rows: list[FindingModel] = []
    skipped = 0
    
    for f in findings:
        key = (f.agent.value, f.asset, f.title)
        if key in existing_set:
            skipped += 1
            continue
            
        rows.append(to_model(f))
        # Add to set so we don't insert duplicates within the same batch
        existing_set.add(key)

    if not rows:
        logger.info("findings.persisted", count=0, deduplicated=skipped)
        return []

    session.add_all(rows)
    await session.commit()
    for row in rows:
        await session.refresh(row)

    logger.info("findings.persisted", count=len(rows), deduplicated=skipped)
    return rows


async def run_agent(
    session: AsyncSession,
    client: AiEngineClient,
    agent: AgentKind,
    request: AgentRunRequest,
) -> list[FindingModel]:
    """Call one ai.engine agent and persist whatever it returns."""
    logger.info("agent.run.start", agent=agent.value, source=request.source, asset=request.asset)

    from app.models.setting import Setting as SettingModel
    
    # Inject LLM credentials and config from settings if present
    for key in ("llm_provider", "llm_model", "llm_base_url", "llm_api_key"):
        setting = await session.get(SettingModel, key)
        if setting and setting.value:
            request.context[key] = setting.value
            
    # Fallback to old key if new key isn't set
    if "llm_api_key" not in request.context:
        api_key_setting = await session.get(SettingModel, "openai_api_key")
        if api_key_setting and api_key_setting.value:
            request.context["llm_api_key"] = api_key_setting.value

    batch = await client.analyze(agent, request)

    if not request.persist:
        logger.info("agent.run.done", agent=agent.value, count=len(batch.findings), persisted=False)
        return [to_model(finding) for finding in batch.findings]

    rows = await persist_findings(session, batch.findings)
    logger.info("agent.run.done", agent=agent.value, count=len(rows), persisted=True)
    return rows
