"""Add indexes for deduplication.

Revision ID: 0003
Revises: 0002
Create date: 2026-08-05

Adds indexes on title and asset to support the Phase 2 deduplication query.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Index for fast deduplication lookups by (agent, title) and (asset)
    op.create_index("ix_findings_title", "findings", ["title"], unique=False)
    op.create_index("ix_findings_asset", "findings", ["asset"], unique=False)
    
    # A composite index would be even better for the specific query, but
    # individual indexes provide flexibility for future queries as well.


def downgrade() -> None:
    op.drop_index("ix_findings_asset", table_name="findings")
    op.drop_index("ix_findings_title", table_name="findings")
