"""Findings query layer.

Filter building and the duplicate lookup both live here, so endpoints read as
"parse query params, call crud, shape response" and the dedup rule has one
definition instead of being inlined in a service.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from cyber_contracts import AgentKind, FindingCreate, FindingStatus, FindingType, Severity
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.elements import ColumnElement, UnaryExpression

from app.crud.crud_base import CRUDBase
from app.models.finding import Finding
from app.schemas.finding import FindingStatusUpdate

# Safety net for findings that belong to neither a run nor a scan: without one of
# those ids there is nothing to scope duplicates to, so fall back to a window.
DEDUPE_WINDOW = timedelta(days=1)

# What makes two findings "the same observation".
#
# `run_id` and `scan_id` are deliberately part of the key. Scoping duplicates to
# the run that produced them is what stops a re-scan from persisting nothing and
# rendering as an empty - therefore apparently clean - run. Suppressing noise
# within one run is useful; hiding a new run's findings because a previous run
# saw them is data loss dressed up as tidiness.
DedupeKey = tuple[
    str,          # agent
    str | None,   # asset
    int | None,   # port
    str | None,   # service
    str,          # finding_type
    str,          # title
    UUID | None,  # run_id
    UUID | None,  # scan_id
    UUID | None,  # message_id
]


def dedupe_key(finding: FindingCreate) -> DedupeKey:
    """The identity of one observation, for duplicate suppression."""
    return (
        finding.agent.value,
        finding.asset,
        finding.port,
        finding.service,
        finding.finding_type.value,
        finding.title,
        finding.run_id,
        finding.scan_id,
        finding.message_id,
    )


def _row_key(row: Finding) -> DedupeKey:
    return (
        row.agent,
        row.asset,
        row.port,
        row.service,
        row.finding_type,
        row.title,
        row.run_id,
        row.scan_id,
        row.message_id,
    )


class CRUDFinding(CRUDBase[Finding, FindingCreate, FindingStatusUpdate]):
    """Findings, with the filters the analyst UI actually asks for."""

    @staticmethod
    def build_filters(
        *,
        agent: AgentKind | None = None,
        severity: Severity | None = None,
        finding_type: FindingType | None = None,
        scan_id: UUID | None = None,
        run_id: UUID | None = None,
        message_id: UUID | None = None,
        asset: str | None = None,
        status: FindingStatus | None = None,
    ) -> list[ColumnElement[bool]]:
        """Translate optional query params into SQLAlchemy predicates."""
        filters: list[ColumnElement[bool]] = []
        if status is not None:
            filters.append(Finding.status == status.value)
        if agent is not None:
            filters.append(Finding.agent == agent.value)
        if severity is not None:
            filters.append(Finding.severity == severity.value)
        if finding_type is not None:
            filters.append(Finding.finding_type == finding_type.value)
        if scan_id is not None:
            filters.append(Finding.scan_id == scan_id)
        if run_id is not None:
            filters.append(Finding.run_id == run_id)
        if message_id is not None:
            filters.append(Finding.message_id == message_id)
        if asset is not None:
            filters.append(Finding.asset == asset)
        return filters

    @staticmethod
    def newest_first() -> UnaryExpression[Any]:
        """Findings are ordered by when the activity was observed, not inserted."""
        return Finding.detected_at.desc()

    async def count_by_severity(
        self, db: AsyncSession, *, filters: list[ColumnElement[bool]] | None = None
    ) -> list[tuple[Severity, int]]:
        """Tally matching findings per severity in one grouped query.

        Counting in Python would mean loading every row for the asset just to
        bucket it, so the cost of a summary would grow with its history.
        """
        statement = (
            select(Finding.severity, func.count())
            .where(*(filters or []))
            .group_by(Finding.severity)
        )
        rows = (await db.execute(statement)).all()
        return [(Severity(severity), int(count)) for severity, count in rows]

    async def open_by_candidate_ids(
        self,
        db: AsyncSession,
        *,
        assets: list[str],
        statuses: tuple[str, ...],
    ) -> list[Finding]:
        """Open findings on these assets that carry a rule-engine candidate id.

        Filtered on the JSONB path rather than a column: ``candidate_id`` lives in
        ``evidence``, and an expression index on ``(evidence->>'candidate_id')``
        keeps the lookup cheap without widening the Finding contract.

        Selecting by asset rather than by candidate id is deliberate. A
        verification pass has to see the findings that are *absent* from the fresh
        scan - those are exactly the ones whose ids it cannot supply.
        """
        if not assets:
            return []

        statement = select(Finding).where(
            Finding.asset.in_(assets),
            Finding.status.in_(statuses),
            Finding.evidence["candidate_id"].astext.isnot(None),
        )
        rows = (await db.execute(statement)).scalars().all()
        return list(rows)

    async def existing_dedupe_keys(
        self, db: AsyncSession, *, findings: list[FindingCreate]
    ) -> set[DedupeKey]:
        """Return the keys of already-stored findings that could collide.

        The query narrows on the two indexed, always-present columns (`agent`,
        `title`) plus the window, then the full key is compared in Python.

        That split is deliberate. Filtering on `asset` in SQL was the previous
        bug: `asset IN (...)` never matches `asset IS NULL`, so any finding
        without an asset escaped deduplication whenever the same batch also
        contained findings that had one.
        """
        if not findings:
            return set()

        agents = {f.agent.value for f in findings}
        titles = {f.title for f in findings}
        cutoff = datetime.now(UTC) - DEDUPE_WINDOW

        statement = select(Finding).where(
            Finding.agent.in_(agents),
            Finding.title.in_(titles),
            Finding.detected_at >= cutoff,
        )
        rows = (await db.execute(statement)).scalars().all()
        return {_row_key(row) for row in rows}


finding = CRUDFinding(Finding)
