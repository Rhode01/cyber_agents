"""Runs table for persistent pipeline status.

Revision ID: 0004
Revises: 0003
Create date: 2026-08-06

Adds the ``runs`` table so the Run Agent page can restore its state after a
browser refresh. Each run stores the scanned target, pipeline mode, a per-agent
status snapshot (JSONB), and the discovery report.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("target", sa.String(length=512), nullable=False),
        sa.Column("mode", sa.String(length=16), nullable=False, server_default="auto"),
        sa.Column(
            "status", sa.String(length=32), nullable=False, server_default="running"
        ),
        sa.Column(
            "agent_statuses",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default="{}",
        ),
        sa.Column("discovery", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column(
            "started_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "mode IN ('auto', 'manual')", name="mode"
        ),
        sa.CheckConstraint(
            "status IN ('running', 'completed', 'completed_with_errors', 'failed')",
            name="status",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_runs"),
    )
    op.create_index("ix_runs_created_at", "runs", ["created_at"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_runs_created_at", table_name="runs")
    op.drop_table("runs")
