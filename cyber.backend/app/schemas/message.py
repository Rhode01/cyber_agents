"""Message intake DTOs.

``MessageRead`` deliberately omits ``raw_content``. The column holds the whole
submitted message; shipping it to the browser on every poll would be wasteful, and
the frontend has no reason to render a raw phishing email - interpreting it is the
agent's job, and rendering it is how a reader gets phished.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from cyber_contracts import MessageFormat, MessageStatus, MessageVerdict
from pydantic import BaseModel, ConfigDict, Field


class MessageRead(BaseModel):
    """One message intake record, as returned by the API."""

    model_config = ConfigDict(from_attributes=True, extra="ignore")

    id: UUID
    filename: str
    format: MessageFormat
    size_bytes: int
    sha256: str
    submitted_url: str | None
    sender: str | None = Field(default=None, description="UNTRUSTED. Render as text.")
    subject: str | None = Field(default=None, description="UNTRUSTED. Render as text.")
    status: MessageStatus
    job_id: str | None
    link_count: int
    attachment_count: int
    finding_count: int
    verdict: MessageVerdict | None = Field(
        default=None,
        description="Null while pending, and after a failure. Different from 'clean'.",
    )
    error: str | None = Field(
        default=None, description="Why this message produced no verdict. Shown verbatim."
    )
    created_at: datetime
    updated_at: datetime
    completed_at: datetime | None


class MessageList(BaseModel):
    """A page of messages."""

    model_config = ConfigDict(extra="forbid")

    items: list[MessageRead] = Field(default_factory=list)
    total: int = Field(ge=0)
    limit: int = Field(ge=1)
    offset: int = Field(ge=0)


class UrlSubmit(BaseModel):
    """A bare URL or domain an analyst pasted in for inspection."""

    model_config = ConfigDict(extra="forbid")

    url: str = Field(
        min_length=1,
        max_length=2048,
        description="An http or https URL. Validated by app.core.urls before storage.",
    )
    enrich: bool = Field(
        default=False,
        description="Fetch the page to follow redirects and look for a credential "
        "form. This CONTACTS THE SUSPECT HOST, so it is off unless asked for.",
    )
