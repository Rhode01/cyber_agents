"""Scan intake and finding detail

Revision ID: 0002
Revises: 0001
Create date: 2026-08-04

Adds the ``scans`` intake table and the seven columns Phase 2 needs on
``findings``.

Two things to know when reading this:

* Order matters. ``scans`` is created first because ``findings.scan_id``
  references it.
* Constraint names are the SHORT form. Base's naming convention in
  ``app/db/base.py`` expands them to ``ck_findings_<name>`` / ``pk_scans`` /
  ``fk_findings_scan_id_scans``, exactly as it does for the ORM models. Passing
  the already-expanded name here would produce ``ck_findings_ck_findings_...``.
* The new non-nullable columns carry a server_default so existing rows can be
  backfilled, and then the default is dropped for ``finding_type`` and
  ``status`` so future inserts have to be explicit about them.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

SCAN_FORMAT_VALUES = ("nmap_xml", "openvas_xml")
SCAN_STATUS_VALUES = ("pending", "parsing", "analyzing", "completed", "failed")
FINDING_TYPE_VALUES = (
    "outdated_service",
    "risky_exposed_service",
    "known_cve",
    "weak_configuration",
    "prompt_injection_attempt",
    "informational",
)
FINDING_STATUS_VALUES = ("new", "triaged", "resolved", "false_positive")


def _in_clause(column: str, values: tuple[str, ...]) -> str:
    rendered = ", ".join(f"'{value}'" for value in values)
    return f"{column} IN ({rendered})"


def upgrade() -> None:
    op.create_table(
        "scans",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("filename", sa.String(length=255), nullable=False),
        sa.Column("format", sa.String(length=32), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("asset", sa.String(length=512), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("job_id", sa.String(length=64), nullable=True),
        sa.Column("host_count", sa.Integer(), nullable=False),
        sa.Column("finding_count", sa.Integer(), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("raw_content", sa.Text(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(_in_clause("format", SCAN_FORMAT_VALUES), name="format"),
        sa.CheckConstraint(_in_clause("status", SCAN_STATUS_VALUES), name="status"),
        sa.CheckConstraint("size_bytes >= 0", name="size_bytes"),
        sa.PrimaryKeyConstraint("id", name="pk_scans"),
    )
    op.create_index("ix_scans_sha256", "scans", ["sha256"], unique=False)
    op.create_index("ix_scans_status", "scans", ["status"], unique=False)
    op.create_index("ix_scans_created_at", "scans", ["created_at"], unique=False)

    # --- findings: the seven new columns ------------------------------------
    op.add_column(
        "findings",
        sa.Column(
            "finding_type",
            sa.String(length=32),
            nullable=False,
            server_default="informational",
        ),
    )
    op.add_column("findings", sa.Column("service", sa.String(length=64), nullable=True))
    op.add_column("findings", sa.Column("port", sa.Integer(), nullable=True))
    op.add_column("findings", sa.Column("protocol", sa.String(length=8), nullable=True))
    op.add_column(
        "findings",
        sa.Column(
            "cve_ids",
            postgresql.ARRAY(sa.Text()),
            nullable=False,
            server_default="{}",
        ),
    )
    op.add_column(
        "findings",
        sa.Column("status", sa.String(length=16), nullable=False, server_default="new"),
    )
    op.add_column(
        "findings", sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=True)
    )
    op.add_column(
        "findings",
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
    )

    # Existing rows are backfilled by now; make new inserts state these explicitly.
    op.alter_column("findings", "finding_type", server_default=None)
    op.alter_column("findings", "status", server_default=None)

    op.create_check_constraint(
        "finding_type", "findings", _in_clause("finding_type", FINDING_TYPE_VALUES)
    )
    op.create_check_constraint("status", "findings", _in_clause("status", FINDING_STATUS_VALUES))
    op.create_check_constraint("port", "findings", "port IS NULL OR (port >= 1 AND port <= 65535)")

    op.create_index("ix_findings_finding_type", "findings", ["finding_type"], unique=False)
    op.create_index("ix_findings_status", "findings", ["status"], unique=False)
    op.create_index("ix_findings_scan_id", "findings", ["scan_id"], unique=False)
    op.create_foreign_key(
        "fk_findings_scan_id_scans",
        "findings",
        "scans",
        ["scan_id"],
        ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint("fk_findings_scan_id_scans", "findings", type_="foreignkey")
    op.drop_index("ix_findings_scan_id", table_name="findings")
    op.drop_index("ix_findings_status", table_name="findings")
    op.drop_index("ix_findings_finding_type", table_name="findings")

    op.drop_constraint("ck_findings_port", "findings", type_="check")
    op.drop_constraint("ck_findings_status", "findings", type_="check")
    op.drop_constraint("ck_findings_finding_type", "findings", type_="check")

    for column in (
        "updated_at",
        "scan_id",
        "status",
        "cve_ids",
        "protocol",
        "port",
        "service",
        "finding_type",
    ):
        op.drop_column("findings", column)

    op.drop_index("ix_scans_created_at", table_name="scans")
    op.drop_index("ix_scans_status", table_name="scans")
    op.drop_index("ix_scans_sha256", table_name="scans")
    op.drop_table("scans")
