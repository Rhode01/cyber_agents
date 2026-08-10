"""The scan intake record.

One row per uploaded scanner report. It exists for three reasons:

* the intake pipeline is asynchronous, so the frontend needs something to poll;
* when the LLM assessment fails the scan is marked ``failed`` with the reason,
  which is what makes "fail loudly" visible to an operator rather than silently
  producing rule-only findings;
* ``raw_content`` keeps the original artifact so a failed scan can be re-run
  without a re-upload, and so ``Finding.raw_reference`` points at something real.

Like the findings table, ``format`` and ``status`` are VARCHAR with CHECK
constraints rather than native PostgreSQL enums - the StrEnums in
``cyber_contracts`` stay the single validator.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from cyber_contracts import ScanFormat, ScanStatus
from sqlalchemy import CheckConstraint, DateTime, Index, Integer, String, Text, func
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

FORMAT_VALUES: tuple[str, ...] = tuple(f.value for f in ScanFormat)
STATUS_VALUES: tuple[str, ...] = tuple(s.value for s in ScanStatus)

# Uploads above this are rejected at the API rather than truncated, so a scan
# never silently represents only part of what was submitted.
MAX_RAW_CONTENT_BYTES = 5 * 1024 * 1024


def _in_clause(column: str, values: tuple[str, ...]) -> str:
    rendered = ", ".join(f"'{value}'" for value in values)
    return f"{column} IN ({rendered})"


class Scan(Base):
    """One uploaded scanner report and the state of its analysis."""

    __tablename__ = "scans"
    __table_args__ = (
        CheckConstraint(_in_clause("format", FORMAT_VALUES), name="format"),
        CheckConstraint(_in_clause("status", STATUS_VALUES), name="status"),
        CheckConstraint("size_bytes >= 0", name="size_bytes"),
        Index("ix_scans_created_at", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        postgresql.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    format: Mapped[str] = mapped_column(String(32), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    asset: Mapped[str | None] = mapped_column(String(512), nullable=True)

    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=ScanStatus.pending.value, index=True
    )
    job_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    host_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    finding_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Why this scan produced nothing. Shown verbatim in the UI.
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    # The original upload. UNTRUSTED: stored and re-parsed, never executed and
    # never shown to an analyst as-is.
    raw_content: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def __repr__(self) -> str:
        return f"<Scan id={self.id} format={self.format} status={self.status}>"
