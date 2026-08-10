"""Baseline: the findings table.

Revision ID: 0001
Revises: None
Create date: 2026-08-03

The single Phase 1 migration. agent and severity are VARCHAR with CHECK
constraints rather than native PostgreSQL enums so that adding a value later is
a constraint swap, not an ALTER TYPE. The Python StrEnums in
cyber_contracts remain the source of truth.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

AGENT_VALUES = ("vulnerability", "phishing", "network", "webapp")
SEVERITY_VALUES = ("info", "low", "medium", "high", "critical")


def _in_clause(column: str, values: tuple[str, ...]) -> str:
    rendered = ", ".join(f"'{value}'" for value in values)
    return f"{column} IN ({rendered})"


def upgrade() -> None:
    op.create_table(
        "findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("agent", sa.String(length=32), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("asset", sa.String(length=512), nullable=True),
        sa.Column(
            "evidence",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default="{}",
            nullable=False,
        ),
        sa.Column("recommendation", sa.Text(), nullable=True),
        sa.Column("raw_reference", sa.String(length=512), nullable=True),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        # Names here are the SHORT form: Base's naming convention expands them to
        # ck_findings_<name>, exactly as it does for the ORM model.
        sa.CheckConstraint(_in_clause("agent", AGENT_VALUES), name="agent"),
        sa.CheckConstraint(_in_clause("severity", SEVERITY_VALUES), name="severity"),
        sa.CheckConstraint("confidence >= 0.0 AND confidence <= 1.0", name="confidence"),
        sa.PrimaryKeyConstraint("id", name="pk_findings"),
    )
    op.create_index("ix_findings_agent", "findings", ["agent"], unique=False)
    op.create_index("ix_findings_severity", "findings", ["severity"], unique=False)
    op.create_index("ix_findings_detected_at", "findings", ["detected_at"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_findings_detected_at", table_name="findings")
    op.drop_index("ix_findings_severity", table_name="findings")
    op.drop_index("ix_findings_agent", table_name="findings")
    op.drop_table("findings")
