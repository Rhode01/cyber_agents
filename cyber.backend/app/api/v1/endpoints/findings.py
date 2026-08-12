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
from app.api.deps import SessionDep, SettingsDep
from app.core.logging import get_logger
from app.core.security import CurrentPrincipal, InternalKeyGuard
from app.schemas.finding import (
    FindingBatchCreate,
    FindingCreate,
    FindingList,
    FindingRead,
    FindingStatusUpdate,
    FindingVerifyRequest,
    FindingVerifyResponse,
)
from app.services.orchestration import persist_findings
from app.services.verification import OPEN_STATUSES
from app.tasks.verification_tasks import enqueue_recheck

logger = get_logger(__name__)

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
    dependencies=[InternalKeyGuard],
    responses={status.HTTP_401_UNAUTHORIZED: {"description": "Missing internal key."}},
)
async def create_finding(
    payload: FindingCreate,
    session: SessionDep,
    principal: CurrentPrincipal,
) -> FindingRead:
    """Store one finding produced by an agent. Service-to-service only."""
    del principal  # Phase 1: every caller is an analyst.
    rows = await persist_findings(session, [payload])
    return FindingRead.model_validate(rows[0])


@router.post(
    "/batch",
    response_model=list[FindingRead],
    status_code=status.HTTP_201_CREATED,
    summary="Persist a batch of findings from one agent",
    dependencies=[InternalKeyGuard],
    responses={status.HTTP_401_UNAUTHORIZED: {"description": "Missing internal key."}},
)
async def create_findings(
    payload: FindingBatchCreate,
    session: SessionDep,
    principal: CurrentPrincipal,
) -> list[FindingRead]:
    """Store every finding in a batch. This is the ai.engine push-back path.

    Guarded by the internal key: it writes to the findings table and no browser
    calls it, so leaving it open made the whole findings store world-writable.
    """
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
    status_filter: Annotated[
        FindingStatus | None,
        Query(alias="status", description="Filter by triage status, e.g. new or resolved."),
    ] = None,
    message_id: Annotated[
        UUID | None, Query(description="Only findings from this submitted message.")
    ] = None,
    asset: Annotated[
        str | None, Query(max_length=512, description="Only findings on this exact asset.")
    ] = None,
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
        message_id=message_id,
        asset=asset,
        status=status_filter,
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
    severities = dict.fromkeys(Severity, 0)
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


@router.post(
    "/verify",
    response_model=FindingVerifyResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Re-check findings to confirm whether they are resolved",
)
async def verify_findings(
    payload: FindingVerifyRequest,
    session: SessionDep,
    settings: SettingsDep,
    principal: CurrentPrincipal,
) -> FindingVerifyResponse:
    """Queue a re-scan of the hosts behind these findings.

    Answers 202: the re-check runs a scan, which takes longer than a request should
    be held open. Poll the findings afterwards - a resolved one carries a
    ``verification`` entry saying what proved it, and one that could not be
    confirmed carries the reason instead.
    """
    del principal

    if payload.finding_ids:
        rows = [
            row
            for row in [
                await crud.finding.get(session, finding_id) for finding_id in payload.finding_ids
            ]
            if row is not None
        ]
    else:
        rows = await crud.finding.open_by_candidate_ids(
            session, assets=[payload.asset or ""], statuses=OPEN_STATUSES
        )

    open_rows = [row for row in rows if row.status in OPEN_STATUSES]
    if not open_rows:
        # 202 with nothing queued rather than a 404: "there is nothing open to
        # re-check" is a successful answer to the question that was asked.
        return FindingVerifyResponse(
            queued=0,
            job_id=None,
            detail="No open findings matched, so nothing was queued for re-checking.",
        )

    job_id = await enqueue_recheck(settings.redis_url, [row.id for row in open_rows])
    logger.info("findings.verify.queued", count=len(open_rows), job_id=job_id)
    return FindingVerifyResponse(
        queued=len(open_rows),
        job_id=job_id,
        detail=(
            f"Re-checking {len(open_rows)} open finding(s). Only a finding whose host and "
            "port are provably re-scanned can be resolved; anything else records why it "
            "could not be confirmed."
        ),
    )


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
