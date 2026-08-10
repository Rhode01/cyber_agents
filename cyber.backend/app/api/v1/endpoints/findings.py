"""Findings endpoints.

The backend owns persistence, so this is where findings enter and leave storage
regardless of who produced them - an inline agent run, an arq job, or the
ai.engine pushing a batch back after a long graph run.
"""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from cyber_contracts import AgentKind, FindingStatus, FindingType, Severity
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field

from app import crud
from app.api.deps import SessionDep
from app.core.security import CurrentPrincipal
from app.schemas.finding import (
    FindingBatchCreate,
    FindingCreate,
    FindingList,
    FindingRead,
    FindingStatusUpdate,
)
from app.services.orchestration import persist_findings

router = APIRouter(prefix="/findings", tags=["findings"])

# The summary endpoint returns whole findings, so it needs a tighter ceiling than
# the list endpoint. An asset with thousands of findings must not be a way to
# pull the table through one request.
SUMMARY_MAX_FINDINGS = 100


class FindingSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    asset: str
    count: int = Field(description="Total findings for this asset, ignoring the page below.")
    severities: dict[Severity, int] = Field(
        description="Full tally across all findings for the asset, not just the page."
    )
    findings: list[FindingRead] = Field(description="The newest findings, capped.")
    truncated: bool = Field(description="True when `count` exceeds the returned page.")


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
    run_id: Annotated[UUID | None, Query(description="Only findings from this run.")] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> FindingList:
    """Return a page of findings, newest observation first."""
    del principal

    filters = crud.finding.build_filters(
        agent=agent,
        severity=severity,
        finding_type=finding_type,
        scan_id=scan_id,
        run_id=run_id,
    )
    total = await crud.finding.count(session, filters=filters)
    rows = await crud.finding.get_multi(
        session,
        filters=filters,
        order_by=crud.finding.newest_first(),
        limit=limit,
        offset=offset,
    )

    return FindingList(
        items=[FindingRead.model_validate(row) for row in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/summary", response_model=FindingSummary, summary="Summarize findings for an asset")
async def summarize_findings(
    asset: Annotated[str, Query(min_length=1, max_length=512, description="Asset to summarize.")],
    session: SessionDep,
    principal: CurrentPrincipal,
    limit: Annotated[int, Query(ge=1, le=SUMMARY_MAX_FINDINGS)] = 25,
) -> FindingSummary:
    """Summarize one asset: a full severity tally plus the newest findings.

    The tally counts every finding for the asset; only the ``findings`` list is
    paged. That split matters - a truncated tally would understate exposure,
    which is the one number an operator reads first.
    """
    del principal

    filters = crud.finding.build_filters(asset=asset)
    total = await crud.finding.count(session, filters=filters)

    # One grouped query for the tally rather than counting in Python over every
    # row, so the response cost does not grow with the asset's history.
    severities = {severity: 0 for severity in Severity}
    for severity, count in await crud.finding.count_by_severity(session, filters=filters):
        severities[severity] = count

    rows = await crud.finding.get_multi(
        session, filters=filters, order_by=crud.finding.newest_first(), limit=limit
    )

    return FindingSummary(
        asset=asset,
        count=total,
        severities=severities,
        findings=[FindingRead.model_validate(row) for row in rows],
        truncated=total > len(rows),
    )


@router.get("/{finding_id}", response_model=FindingRead, summary="Fetch one finding")
async def get_finding(
    finding_id: UUID,
    session: SessionDep,
    principal: CurrentPrincipal,
) -> FindingRead:
    """Return a single finding by id."""
    del principal
    row = await crud.finding.get(session, finding_id)
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
    row = await crud.finding.get(session, finding_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")

    updated = await crud.finding.update(session, db_obj=row, obj_in=payload)
    return FindingRead.model_validate(updated)


@router.delete(
    "/{finding_id}",
    response_model=FindingRead,
    summary="Dismiss a finding as a false positive",
)
async def dismiss_finding(
    finding_id: UUID,
    session: SessionDep,
    principal: CurrentPrincipal,
) -> FindingRead:
    """Mark a finding ``false_positive`` rather than deleting the row.

    This used to be a hard DELETE, which contradicted the rule the PATCH handler
    states: a finding records what an agent observed at a point in time, and
    destroying that destroys the audit trail. Dismissing is what an analyst
    actually wants, it is reversible, and the row still evidences that the agent
    saw something.
    """
    del principal
    row = await crud.finding.get(session, finding_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")

    updated = await crud.finding.update(
        session, db_obj=row, obj_in={"status": FindingStatus.false_positive.value}
    )
    return FindingRead.model_validate(updated)
