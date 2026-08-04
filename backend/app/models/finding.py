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

from cyberagents_contracts import AgentKind, Severity
from sqlalchemy import CheckConstraint, DateTime, Float, Index, String, Text, func
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

AGENT_VALUES: tuple[str, ...] = tuple(a.value for a in AgentKind)
SEVERITY_VALUES: tuple[str, ...] = tuple(s.value for s in Severity)


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
        Index("ix_findings_detected_at", "detected_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        postgresql.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    agent: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    asset: Mapped[str | None] = mapped_column(String(512), nullable=True)

    # Untrusted data lifted from the ingested artifact. Stored and displayed,
    # never interpolated into a prompt unfenced.
    evidence: Mapped[dict[str, Any]] = mapped_column(
        postgresql.JSONB, nullable=False, default=dict, server_default="{}"
    )

    recommendation: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_reference: Mapped[str | None] = mapped_column(String(512), nullable=True)

    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    def __repr__(self) -> str:
        return f"<Finding id={self.id} agent={self.agent} severity={self.severity}>"
