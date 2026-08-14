"""The scan scope table.

One row is one authorisation: "this platform may scan this range, and here is who
said so". The MCP server reads it at scan time, unioned with the static allowlist
in its own config.

The static config list does not go away. It holds the ranges that are true of the
deployment itself - loopback, the private network the stack runs on - which should
not depend on a database being up. This table holds what an operator adds for a
client, which should not depend on a redeploy.

``network`` is stored as text rather than as PostgreSQL's ``cidr`` type. The check
that matters happens in Python, in one place, against the same ``ipaddress`` module
the rest of the target policy uses; a second dialect-specific implementation of
"is this address in this range" is a second thing that can disagree.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Index, String, func
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class ScanScope(Base):
    """One range this platform is authorised to scan."""

    __tablename__ = "scan_scope"
    __table_args__ = (
        # The scan-time read is "every active entry", so that is what is indexed.
        Index("ix_scan_scope_active", "active"),
        Index("ix_scan_scope_created_at", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        postgresql.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )

    # The canonical CIDR, always with a prefix - a bare address is stored as /32
    # or /128 - so the scan-time check is one shape.
    network: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)

    # What the operator typed. Display only; never consulted when deciding scope,
    # because a hostname here would let DNS choose what gets scanned.
    requested: Mapped[str] = mapped_column(String(255), nullable=False, default="")

    label: Mapped[str] = mapped_column(String(120), nullable=False, default="")

    # Who attested that this is in scope. Recorded, never verified - there is no
    # identity system yet, and a name written down at the moment of the claim is
    # worth more than nothing at all.
    authorized_by: Mapped[str] = mapped_column(String(120), nullable=False)
    note: Mapped[str] = mapped_column(String(2000), nullable=False, default="")

    # Revocation is a flag rather than a delete, so "who authorised this scan, and
    # when was it withdrawn" survives the withdrawal.
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )

    def __repr__(self) -> str:
        return f"<ScanScope network={self.network} active={self.active}>"
