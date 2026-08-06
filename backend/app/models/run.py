"""The Run table.

A run is one pipeline execution from the Run Agent page: the target it scanned,
the pipeline mode, and a per-agent status snapshot. It exists so a browser
refresh can restore the run's live state instead of losing it. The findings
themselves live in the ``findings`` table; ``agent_statuses`` only keeps the
per-agent snapshot the UI renders (state, finding ids/counts, error message).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import CheckConstraint, DateTime, Index, String, func
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

RUN_STATUS_VALUES: tuple[str, ...] = (
    "running",
    "completed",
    "completed_with_errors",
    "failed",
)
PIPELINE_MODE_VALUES: tuple[str, ...] = ("auto", "manual")


class Run(Base):
    """A single pipeline execution and its per-agent status snapshot."""

    __tablename__ = "runs"
    __table_args__ = (
        CheckConstraint(
            "status IN ('running', 'completed', 'completed_with_errors', 'failed')",
            name="status",
        ),
        CheckConstraint("mode IN ('auto', 'manual')", name="mode"),
        Index("ix_runs_created_at", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        postgresql.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    target: Mapped[str] = mapped_column(String(512), nullable=False)
    mode: Mapped[str] = mapped_column(String(16), nullable=False, default="auto")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="running")

    # Per-agent snapshot keyed by agent kind: {state, findings, error}. Untrusted
    # only in the sense that agent titles/errors come from scanners; stored and
    # displayed as text.
    agent_statuses: Mapped[dict[str, Any]] = mapped_column(
        postgresql.JSONB, nullable=False, default=dict, server_default="{}"
    )

    # The discovery report for this run (interfaces, subnets, live/web hosts).
    discovery: Mapped[dict[str, Any] | None] = mapped_column(
        postgresql.JSONB, nullable=True
    )

    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )

    def __repr__(self) -> str:
        return f"<Run id={self.id} target={self.target} status={self.status}>"
