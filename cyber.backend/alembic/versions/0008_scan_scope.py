"""Scan scope table.

Revision ID: 0008
Revises: 0007
Create date: 2026-08-14

Adds ``scan_scope`` so the hosts this platform may scan are data an operator
manages from the UI, rather than a config value that needs a redeploy. The
static allowlist in the MCP server's own config stays: it holds what is true of
the deployment, this table holds what is true of a client engagement.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "scan_scope",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("network", sa.String(length=64), nullable=False),
        sa.Column("requested", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("label", sa.String(length=120), nullable=False, server_default=""),
        sa.Column("authorized_by", sa.String(length=120), nullable=False),
        sa.Column("note", sa.String(length=2000), nullable=False, server_default=""),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
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
        sa.PrimaryKeyConstraint("id"),
        # One row per range: re-adding an existing range updates it rather than
        # leaving two rows that could be revoked independently and disagree.
        sa.UniqueConstraint("network", name="uq_scan_scope_network"),
    )
    op.create_index("ix_scan_scope_active", "scan_scope", ["active"])
    op.create_index("ix_scan_scope_created_at", "scan_scope", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_scan_scope_created_at", table_name="scan_scope")
    op.drop_index("ix_scan_scope_active", table_name="scan_scope")
    op.drop_table("scan_scope")
