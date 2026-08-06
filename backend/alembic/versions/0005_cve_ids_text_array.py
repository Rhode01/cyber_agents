"""Normalise findings.cve_ids to a native text array.

Revision ID: 0005
Revises: 0004
Create date: 2026-08-06

The ORM model and migration 0002 declare ``cve_ids`` as ``TEXT[]`` so a later
phase can filter and join on it. Some environments were created with a ``jsonb``
column instead, which rejects the ``text[]`` bind parameter the model sends and
breaks every finding insert. This migration rewrites the column to match the
model, preserving any JSON array payloads. On databases that already have
``TEXT[]`` the migration is a structural no-op (it rebuilds the column but keeps
the values).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE findings ADD COLUMN cve_ids_new TEXT[] NOT NULL DEFAULT '{}'"
    )
    op.execute(
        """
        UPDATE findings
        SET cve_ids_new = ARRAY(SELECT jsonb_array_elements_text(cve_ids))
        WHERE jsonb_typeof(cve_ids) = 'array'
        """
    )
    op.drop_column("findings", "cve_ids")
    op.alter_column("findings", "cve_ids_new", new_column_name="cve_ids")


def downgrade() -> None:
    op.execute(
        "ALTER TABLE findings ADD COLUMN cve_ids_new JSONB NOT NULL DEFAULT '{}'::jsonb"
    )
    op.execute(
        """
        UPDATE findings
        SET cve_ids_new = to_jsonb(cve_ids)
        WHERE cardinality(cve_ids) > 0
        """
    )
    op.drop_column("findings", "cve_ids")
    op.alter_column("findings", "cve_ids_new", new_column_name="cve_ids")
