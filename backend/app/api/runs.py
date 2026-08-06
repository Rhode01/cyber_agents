"""Run status endpoints.

Runs exist so the Run Agent page can survive a refresh: the backend owns
persistence, so the per-agent status snapshot and discovery report are stored
here and replayed when the page reloads mid-run or after completion.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import func, select

from app.api.deps import SessionDep
from app.core.security import CurrentPrincipal
from app.models.run import Run as RunModel
from app.schemas.run import RunCreate, RunList, RunRead, RunStatus, RunUpdate

router = APIRouter(prefix="/runs", tags=["runs"])


def _to_read(row: RunModel) -> RunRead:
    return RunRead(
        id=row.id,
        target=row.target,
        mode=row.mode,
        status=row.status,
        agent_statuses=row.agent_statuses,
        discovery=row.discovery,
        started_at=row.started_at,
        finished_at=row.finished_at,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


@router.post(
    "",
    response_model=RunRead,
    status_code=status.HTTP_201_CREATED,
    summary="Create a run",
)
async def create_run(
    payload: RunCreate,
    session: SessionDep,
    principal: CurrentPrincipal,
) -> RunRead:
    """Start a new run with every agent pending."""
    del principal
    row = RunModel(target=payload.target, mode=payload.mode)
    session.add(row)
    await session.commit()
    await session.refresh(row)
    return _to_read(row)


@router.get("", response_model=RunList, summary="List runs")
async def list_runs(
    session: SessionDep,
    principal: CurrentPrincipal,
    limit: int = 20,
) -> RunList:
    """Return the most recent runs, newest first."""
    del principal
    total = int((await session.execute(select(func.count()).select_from(RunModel))).scalar_one())
    stmt = select(RunModel).order_by(RunModel.created_at.desc()).limit(min(limit, 100))
    rows = (await session.execute(stmt)).scalars().all()
    return RunList(items=[_to_read(row) for row in rows], total=total)


@router.get("/latest", response_model=RunRead, summary="Fetch the most recent run")
async def latest_run(
    session: SessionDep,
    principal: CurrentPrincipal,
) -> RunRead:
    """Return the newest run, so a refreshed page can restore its state."""
    del principal
    row = (
        await session.execute(select(RunModel).order_by(RunModel.created_at.desc()).limit(1))
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No runs yet")
    return _to_read(row)


@router.get("/status", response_model=RunStatus, summary="Whether a scan is currently running")
async def run_status(
    session: SessionDep,
    principal: CurrentPrincipal,
) -> RunStatus:
    """Return the newest in-flight run, if any, for the sidebar status indicator."""
    del principal
    row = (
        await session.execute(
            select(RunModel)
            .where(RunModel.status == "running")
            .order_by(RunModel.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    if row is None:
        return RunStatus(scanning=False)
    return RunStatus(scanning=True, current=_to_read(row))


@router.get("/{run_id}", response_model=RunRead, summary="Fetch one run")
async def get_run(
    run_id: uuid.UUID,
    session: SessionDep,
    principal: CurrentPrincipal,
) -> RunRead:
    """Return a single run by id."""
    del principal
    row = await session.get(RunModel, run_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Run not found")
    return _to_read(row)


@router.patch("/{run_id}", response_model=RunRead, summary="Update run status")
async def update_run(
    run_id: uuid.UUID,
    payload: RunUpdate,
    session: SessionDep,
    principal: CurrentPrincipal,
) -> RunRead:
    """Update a run's live state: per-agent statuses, discovery, or completion."""
    del principal
    row = await session.get(RunModel, run_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Run not found")

    if payload.status is not None:
        row.status = payload.status
        if payload.status == "running":
            row.finished_at = None
        else:
            row.finished_at = row.finished_at or datetime.now(UTC)
    if payload.agent_statuses is not None:
        row.agent_statuses = payload.agent_statuses
    if payload.discovery is not None:
        row.discovery = payload.discovery

    await session.commit()
    await session.refresh(row)
    return _to_read(row)
