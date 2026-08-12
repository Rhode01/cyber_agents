"""Index the rule engine's candidate id inside evidence.

Revision ID: 0007
Revises: 0006
Create date: 2026-08-11

The verification loop joins a stored finding to a fresh scan on the candidate id
the rule engine produced - content-addressed, and stable across runs so that the
same fact keeps the same id. It lives in the ``evidence`` JSONB rather than a
column: promoting it would widen the shared Finding contract for something only the
backend's verification service needs.

An expression index makes ``evidence->>'candidate_id'`` cheap to filter on. Mirrored
in the ORM's ``__table_args__`` so the models and the migrations stay in step, which
``tests/unit/test_migrations.py`` asserts.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # sa.text, not a plain string: a string in this list is treated as a column
    # name and rendered quoted, producing ON findings ("(evidence->>'candidate_id')")
    # - which fails, because no column by that name exists.
    op.create_index(
        "ix_findings_evidence_candidate_id",
        "findings",
        [sa.text("(evidence->>'candidate_id')")],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_findings_evidence_candidate_id", table_name="findings")
