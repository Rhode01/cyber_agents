"""The message intake record.

One row per submitted phishing artifact - an uploaded ``.eml`` or a URL an
analyst pasted in. It is the message-side counterpart of ``app.models.scan`` and
exists for the same three reasons:

* analysis is asynchronous, so the frontend needs something to poll;
* when the assessment fails the row is marked ``failed`` with the reason, which
  is what makes "fail loudly" visible instead of quietly producing a verdict
  nobody should trust;
* ``raw_content`` keeps the original artifact so a failed message can be
  re-analysed without a re-upload, and so ``Finding.raw_reference`` points at
  something real.

A separate table rather than a ``format`` on ``scans``: the columns genuinely
differ (a message has a sender and a link count, not hosts and open ports), and
the two intakes fail for different reasons.

Like the findings and scans tables, ``format``/``status``/``verdict`` are VARCHAR
with CHECK constraints rather than native PostgreSQL enums - the StrEnums in
``cyber_contracts`` stay the single validator.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from cyber_contracts import MessageFormat, MessageStatus, MessageVerdict
from sqlalchemy import CheckConstraint, DateTime, Index, Integer, String, Text, func
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

FORMAT_VALUES: tuple[str, ...] = tuple(f.value for f in MessageFormat)
STATUS_VALUES: tuple[str, ...] = tuple(s.value for s in MessageStatus)
VERDICT_VALUES: tuple[str, ...] = tuple(v.value for v in MessageVerdict)

# Well under the 5 MB scan cap: a mail server that accepts a 2 MB message is
# already unusual, and the cap is what stops a single upload from filling the
# column. Rejected at the API rather than truncated, so a stored message never
# represents only part of what was submitted.
MAX_RAW_CONTENT_BYTES = 2 * 1024 * 1024


def _in_clause(column: str, values: tuple[str, ...]) -> str:
    rendered = ", ".join(f"'{value}'" for value in values)
    return f"{column} IN ({rendered})"


class Message(Base):
    """One submitted message or URL, and the state of its analysis."""

    __tablename__ = "messages"
    __table_args__ = (
        # Short names on purpose: Base's NAMING_CONVENTION expands them to
        # ck_messages_<name>. Passing the expanded name here would produce
        # ck_messages_ck_messages_status.
        CheckConstraint(_in_clause("format", FORMAT_VALUES), name="format"),
        CheckConstraint(_in_clause("status", STATUS_VALUES), name="status"),
        CheckConstraint(
            f"verdict IS NULL OR {_in_clause('verdict', VERDICT_VALUES)}", name="verdict"
        ),
        CheckConstraint("size_bytes >= 0", name="size_bytes"),
        Index("ix_messages_created_at", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        postgresql.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    format: Mapped[str] = mapped_column(String(32), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    # The URL an analyst pasted, when there was no file. Operator-supplied and
    # syntactically validated at the API, but still shown as text, never markup.
    submitted_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)

    # Denormalised from the parsed message so a list view can show who it claims
    # to be from without re-parsing. UNTRUSTED - whatever the sender wrote.
    sender: Mapped[str | None] = mapped_column(String(320), nullable=True)
    subject: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=MessageStatus.pending.value, index=True
    )
    job_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    link_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    attachment_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    finding_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # The headline answer, denormalised so the list view does not join findings.
    # Nullable because an unanalysed or failed message has no verdict - which is
    # deliberately different from a verdict of "clean".
    verdict: Mapped[str | None] = mapped_column(String(16), nullable=True, index=True)

    # Why this message produced no verdict. Shown verbatim in the UI.
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    # The original upload, held as a latin-1 transcoding of the submitted bytes
    # so `raw_content.encode("latin-1")` is byte-identical to what arrived. Mail
    # is frequently not valid UTF-8, and a lossy round-trip would change the
    # bytes the parser and the sha256 disagree about later.
    # UNTRUSTED: stored and re-parsed, never executed, never rendered as markup.
    raw_content: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def __repr__(self) -> str:
        return f"<Message id={self.id} format={self.format} status={self.status}>"
