"""Message intake, and the two phishing finding types.

Revision ID: 0006
Revises: 0005
Create date: 2026-08-11

Three changes, in an order that matters:

1. ``messages`` is created first, because step 3 adds a foreign key pointing at
   it.
2. ``ck_findings_finding_type`` is dropped and recreated. A CHECK constraint
   enumerating enum values cannot be extended in place, and this is the cost of
   choosing VARCHAR + CHECK over a native enum - paid deliberately, because the
   alternative is an ALTER TYPE that cannot run inside a transaction.
3. ``findings.message_id`` is added last, with ``ON DELETE SET NULL`` so removing
   a message never destroys findings an analyst may already be working from.

Constraint and index names are spelled out here rather than derived: Alembic's
``op.*`` helpers do not apply ``app/db/base.py``'s naming convention, so the names
below are the already-expanded forms the ORM's convention produces.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Spelled out rather than imported from cyber_contracts on purpose. A migration
# records what the schema became at this revision; importing the live enum would
# make an old migration silently change meaning the next time the enum grows,
# and replaying history would then produce a different database.
MESSAGE_FORMAT_VALUES: tuple[str, ...] = ("email_mime", "url")
MESSAGE_STATUS_VALUES: tuple[str, ...] = (
    "pending",
    "parsing",
    "analyzing",
    "completed",
    "failed",
)
MESSAGE_VERDICT_VALUES: tuple[str, ...] = ("clean", "suspicious", "phishing")

FINDING_TYPES_BEFORE: tuple[str, ...] = (
    "outdated_service",
    "risky_exposed_service",
    "known_cve",
    "weak_configuration",
    "prompt_injection_attempt",
    "informational",
)
# Spelled out in full rather than sliced from the tuple above: the rendered SQL
# has to match the ORM's declaration order, which follows the enum, and a slice
# expression hides whether it still does.
FINDING_TYPES_AFTER: tuple[str, ...] = (
    "outdated_service",
    "risky_exposed_service",
    "known_cve",
    "weak_configuration",
    "prompt_injection_attempt",
    "phishing_message",
    "malicious_url",
    "informational",
)


def _in_clause(column: str, values: tuple[str, ...]) -> str:
    rendered = ", ".join(f"'{value}'" for value in values)
    return f"{column} IN ({rendered})"


def upgrade() -> None:
    # ---- 1. the messages table ---------------------------------------------
    op.create_table(
        "messages",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("filename", sa.String(length=255), nullable=False),
        sa.Column("format", sa.String(length=32), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("submitted_url", sa.String(length=2048), nullable=True),
        sa.Column("sender", sa.String(length=320), nullable=True),
        sa.Column("subject", sa.String(length=1024), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("job_id", sa.String(length=64), nullable=True),
        sa.Column("link_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("attachment_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("finding_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("verdict", sa.String(length=16), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("raw_content", sa.Text(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_messages"),
        # SHORT names. op.create_table runs through Base.metadata's naming
        # convention (env.py binds it as target_metadata), so it expands these to
        # ck_messages_<name>. Passing the expanded form yields
        # ck_messages_ck_messages_format - which is what the DDL-vs-ORM parity
        # test caught here, for the second time in this project's life.
        sa.CheckConstraint(_in_clause("format", MESSAGE_FORMAT_VALUES), name="format"),
        sa.CheckConstraint(_in_clause("status", MESSAGE_STATUS_VALUES), name="status"),
        sa.CheckConstraint(
            f"verdict IS NULL OR {_in_clause('verdict', MESSAGE_VERDICT_VALUES)}",
            name="verdict",
        ),
        sa.CheckConstraint("size_bytes >= 0", name="size_bytes"),
    )
    op.create_index("ix_messages_sha256", "messages", ["sha256"], unique=False)
    op.create_index("ix_messages_status", "messages", ["status"], unique=False)
    op.create_index("ix_messages_verdict", "messages", ["verdict"], unique=False)
    op.create_index("ix_messages_created_at", "messages", ["created_at"], unique=False)

    # ---- 2. widen the finding_type CHECK -----------------------------------
    # SHORT name on the drop as well as the create. `drop_constraint` runs through
    # Base.metadata's naming convention exactly like `create_check_constraint` does, so
    # passing the already-expanded "ck_findings_finding_type" emitted
    # `DROP CONSTRAINT ck_findings_ck_findings_finding_type` and failed against a real
    # database. The offline `--sql` render did not catch it, because the correct name still
    # appeared elsewhere in the script from the CREATE in 0002.
    op.drop_constraint("finding_type", "findings", type_="check")
    op.create_check_constraint(
        "finding_type", "findings", _in_clause("finding_type", FINDING_TYPES_AFTER)
    )

    # ---- 3. link findings to their message ---------------------------------
    op.add_column(
        "findings", sa.Column("message_id", postgresql.UUID(as_uuid=True), nullable=True)
    )
    op.create_index("ix_findings_message_id", "findings", ["message_id"], unique=False)
    op.create_foreign_key(
        "fk_findings_message_id_messages",
        "findings",
        "messages",
        ["message_id"],
        ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint("fk_findings_message_id_messages", "findings", type_="foreignkey")
    op.drop_index("ix_findings_message_id", table_name="findings")
    op.drop_column("findings", "message_id")

    # Any phishing finding would violate the narrower constraint, so it is
    # reclassified rather than deleted. Losing the specific type is recoverable;
    # losing the finding is not.
    op.execute(
        "UPDATE findings SET finding_type = 'informational' "
        "WHERE finding_type IN ('phishing_message', 'malicious_url')"
    )
    # Short name here too - see the note in upgrade().
    op.drop_constraint("finding_type", "findings", type_="check")
    op.create_check_constraint(
        "finding_type", "findings", _in_clause("finding_type", FINDING_TYPES_BEFORE)
    )

    op.drop_index("ix_messages_created_at", table_name="messages")
    op.drop_index("ix_messages_verdict", table_name="messages")
    op.drop_index("ix_messages_status", table_name="messages")
    op.drop_index("ix_messages_sha256", table_name="messages")
    op.drop_table("messages")
