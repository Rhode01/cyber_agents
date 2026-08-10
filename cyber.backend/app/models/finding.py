"""The Finding table.

``agent`` and ``severity`` are stored as VARCHAR with CHECK constraints rather
than native PostgreSQL enums: the Python StrEnum in the shared contracts package
stays the single validator, and adding a severity level later is a one-line
constraint swap instead of an ALTER TYPE dance.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from cyber_contracts import AgentKind, FindingStatus, FindingType, Severity
from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

AGENT_VALUES: tuple[str, ...] = tuple(a.value for a in AgentKind)
SEVERITY_VALUES: tuple[str, ...] = tuple(s.value for s in Severity)
FINDING_TYPE_VALUES: tuple[str, ...] = tuple(t.value for t in FindingType)
FINDING_STATUS_VALUES: tuple[str, ...] = tuple(s.value for s in FindingStatus)


def _in_clause(column: str, values: tuple[str, ...]) -> str:
    rendered = ", ".join(f"'{v}'" for v in values)
    return f"{column} IN ({rendered})"


class Finding(Base):
    """A single detection result produced by one of the four agents."""

    __tablename__ = "findings"
    __table_args__ = (
        CheckConstraint(_in_clause("agent", AGENT_VALUES), name="agent"),
        CheckConstraint(_in_clause("severity", SEVERITY_VALUES), name="severity"),
        CheckConstraint("confidence >= 0.0 AND confidence <= 1.0", name="confidence"),
        CheckConstraint(_in_clause("finding_type", FINDING_TYPE_VALUES), name="finding_type"),
        CheckConstraint(_in_clause("status", FINDING_STATUS_VALUES), name="status"),
        CheckConstraint("port IS NULL OR (port >= 1 AND port <= 65535)", name="port"),
        Index("ix_findings_detected_at", "detected_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        postgresql.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    agent: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    finding_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    asset: Mapped[str | None] = mapped_column(String(512), nullable=True)
    service: Mapped[str | None] = mapped_column(String(64), nullable=True)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(8), nullable=True)

    # Native Postgres text[] rather than JSONB: these are a flat list of tokens
    # that a later phase will want to filter and join on.
    cve_ids: Mapped[list[str]] = mapped_column(
        postgresql.ARRAY(Text), nullable=False, default=list, server_default="{}"
    )

    # Untrusted data lifted from the ingested artifact. Stored and displayed,
    # never interpolated into a prompt unfenced.
    evidence: Mapped[dict[str, Any]] = mapped_column(
        postgresql.JSONB, nullable=False, default=dict, server_default="{}"
    )

    recommendation: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=FindingStatus.new.value, index=True
    )

    # SET NULL rather than CASCADE: deleting a scan record must never destroy the
    # findings an analyst may already be working from.
    # No explicit name: Base's convention derives fk_findings_scan_id_scans, which
    # is what migration 0002 creates. Passing name= here would override the
    # convention and silently diverge from the migration.
    scan_id: Mapped[uuid.UUID | None] = mapped_column(
        postgresql.UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    # Same SET NULL rationale as scan_id: deleting a run record must never
    # destroy the findings an analyst may already be working from.
    # No explicit name: Base's convention derives fk_findings_run_id_runs.
    run_id: Mapped[uuid.UUID | None] = mapped_column(
        postgresql.UUID(as_uuid=True),
        ForeignKey("runs.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    raw_reference: Mapped[str | None] = mapped_column(String(512), nullable=True)

    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )

    def __repr__(self) -> str:
        return f"<Finding id={self.id} agent={self.agent} severity={self.severity}>"
