"""Findings endpoints.

The backend owns persistence, so this is where findings enter and leave storage
regardless of who produced them - an inline agent run, an arq job, or the
ai.engine pushing a batch back after a long graph run.
"""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from cyberagents_contracts import AgentKind, FindingType, Severity
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import func, select

from app.api.deps import SessionDep
from app.core.security import CurrentPrincipal
from app.models.finding import Finding as FindingModel
from app.schemas.finding import (
    FindingBatchCreate,
    FindingCreate,
    FindingList,
    FindingRead,
    FindingStatusUpdate,
)
from app.services.orchestration import persist_findings

router = APIRouter(prefix="/findings", tags=["findings"])


class FindingSummary(BaseModel):
    asset: str
    count: int
    severities: dict[str, int]
    findings: list[FindingRead]


@router.post(
    "",
    response_model=FindingRead,
    status_code=status.HTTP_201_CREATED,
    summary="Persist a single finding",
)
async def create_finding(
    payload: FindingCreate,
    session: SessionDep,
    principal: CurrentPrincipal,
) -> FindingRead:
    """Store one finding produced by an agent."""
    del principal  # Phase 1: every caller is an analyst.
    rows = await persist_findings(session, [payload])
    return FindingRead.model_validate(rows[0])


@router.post(
    "/batch",
    response_model=list[FindingRead],
    status_code=status.HTTP_201_CREATED,
    summary="Persist a batch of findings from one agent",
)
async def create_findings(
    payload: FindingBatchCreate,
    session: SessionDep,
    principal: CurrentPrincipal,
) -> list[FindingRead]:
    """Store every finding in a batch. This is the ai.engine push-back path."""
    del principal
    rows = await persist_findings(session, payload.findings)
    return [FindingRead.model_validate(row) for row in rows]


@router.get("", response_model=FindingList, summary="List findings")
async def list_findings(
    session: SessionDep,
    principal: CurrentPrincipal,
    agent: Annotated[AgentKind | None, Query(description="Filter by producing agent.")] = None,
    severity: Annotated[Severity | None, Query(description="Filter by severity.")] = None,
    finding_type: Annotated[FindingType | None, Query(description="Filter by kind.")] = None,
    scan_id: Annotated[UUID | None, Query(description="Only findings from this scan.")] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> FindingList:
    """Return a page of findings, newest observation first."""
    del principal

    filters = []
    if agent is not None:
        filters.append(FindingModel.agent == agent.value)
    if severity is not None:
        filters.append(FindingModel.severity == severity.value)
    if finding_type is not None:
        filters.append(FindingModel.finding_type == finding_type.value)
    if scan_id is not None:
        filters.append(FindingModel.scan_id == scan_id)

    count_stmt = select(func.count()).select_from(FindingModel).where(*filters)
    total = int((await session.execute(count_stmt)).scalar_one())

    page_stmt = (
        select(FindingModel)
        .where(*filters)
        .order_by(FindingModel.detected_at.desc())
        .limit(limit)
        .offset(offset)
    )
    rows = (await session.execute(page_stmt)).scalars().all()

    return FindingList(
        items=[FindingRead.model_validate(row) for row in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/summary", response_model=FindingSummary, summary="Summarize findings for an asset")
async def summarize_findings(
    asset: Annotated[str, Query(description="The asset to summarize.")],
    session: SessionDep,
    principal: CurrentPrincipal,
) -> FindingSummary:
    """Return a summary of findings for a specific asset."""
    del principal
    
    stmt = (
        select(FindingModel)
        .where(FindingModel.asset == asset)
        .order_by(FindingModel.detected_at.desc())
    )
    rows = (await session.execute(stmt)).scalars().all()
    
    severities = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for row in rows:
        sev = row.severity
        if sev in severities:
            severities[sev] += 1
            
    return FindingSummary(
        asset=asset,
        count=len(rows),
        severities=severities,
        findings=[FindingRead.model_validate(row) for row in rows],
    )


@router.get("/{finding_id}", response_model=FindingRead, summary="Fetch one finding")
async def get_finding(
    finding_id: UUID,
    session: SessionDep,
    principal: CurrentPrincipal,
) -> FindingRead:
    """Return a single finding by id."""
    del principal
    row = await session.get(FindingModel, finding_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    return FindingRead.model_validate(row)


@router.patch("/{finding_id}", response_model=FindingRead, summary="Update triage status")
async def update_finding_status(
    finding_id: UUID,
    payload: FindingStatusUpdate,
    session: SessionDep,
    principal: CurrentPrincipal,
) -> FindingRead:
    """Move a finding through the analyst workflow.

    Status is the only mutable field: everything else records what an agent
    observed, and rewriting that would destroy the audit trail.
    """
    del principal
    row = await session.get(FindingModel, finding_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")

    row.status = payload.status.value
    await session.commit()
    await session.refresh(row)
    return FindingRead.model_validate(row)


@router.delete(
    "/{finding_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete one finding",
)
async def delete_finding(
    finding_id: UUID,
    session: SessionDep,
    principal: CurrentPrincipal,
) -> None:
    """Delete a single finding by id."""
    del principal
    row = await session.get(FindingModel, finding_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")

    await session.delete(row)
    await session.commit()
