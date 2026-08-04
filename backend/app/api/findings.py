"""Findings endpoints.

The backend owns persistence, so this is where findings enter and leave storage
regardless of who produced them - an inline agent run, an arq job, or the
ai.engine pushing a batch back after a long graph run.
"""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from cyberagents_contracts import AgentKind, Severity
from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import func, select

from app.api.deps import SessionDep
from app.core.security import CurrentPrincipal
from app.models.finding import Finding as FindingModel
from app.schemas.finding import FindingBatchCreate, FindingCreate, FindingList, FindingRead
from app.services.orchestration import persist_findings

router = APIRouter(prefix="/findings", tags=["findings"])


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
