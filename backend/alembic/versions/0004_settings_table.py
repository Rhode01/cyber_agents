"""Settings table for configuration storage.

Revision ID: 0004
Revises: 0003
Create date: 2026-08-05

Adds the settings table to hold platform configuration like OpenAI API keys.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "settings",
        sa.Column("key", sa.String(length=100), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("key", name="pk_settings"),
    )


def downgrade() -> None:
    op.drop_table("settings")
