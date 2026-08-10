"""Link findings to the pipeline run that produced them.

Revision ID: 0007
Revises: 0006
Create date: 2026-08-06

Adds the nullable ``runs.id`` foreign key to ``findings`` so the scans page can
group findings into per-run sessions instead of merging every run on the same
target and day together. Deletion is SET NULL: deleting a run must never destroy
the findings an analyst may already be working from.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "findings", sa.Column("run_id", postgresql.UUID(as_uuid=True), nullable=True)
    )
    op.create_index("ix_findings_run_id", "findings", ["run_id"], unique=False)
    op.create_foreign_key(
        "fk_findings_run_id_runs",
        "findings",
        "runs",
        ["run_id"],
        ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint("fk_findings_run_id_runs", "findings", type_="foreignkey")
    op.drop_index("ix_findings_run_id", table_name="findings")
    op.drop_column("findings", "run_id")
