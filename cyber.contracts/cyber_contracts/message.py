"""The normalized message contract.

Parsing lives in the backend and reasoning lives in the ai.engine, so the
*parsed* shape crosses the wire and has to be defined once for both. This is the
email/URL counterpart of ``cyber_contracts.scan``.

**Almost every string here is attacker-authored.** A phishing email is a document
written specifically to manipulate whoever reads it, and the reader downstream of
this contract is a language model. Subjects, display names, addresses, anchor
text, body text and attachment filenames are all whatever the sender chose to
put there. They are carried through verbatim - deliberately, because sanitising
at the parse boundary would destroy the evidence the injection detector needs and
would imply a safety that does not exist. They are fenced exactly once, at the
prompt boundary, by ``app.agents.common.untrusted.wrap_untrusted``.

Two things are deliberately **not** carried, and both omissions are load-bearing:

* **The raw HTML body.** Only ``body_text``, a ``body_html_present`` flag, and
  the links extracted from the markup. The HTML is the largest and most
  dangerous part of the artifact and nothing downstream needs it; not carrying it
  means it can never reach a prompt or a browser.
* **Attachment bytes.** Hashed, sized, and discarded at the parse boundary. The
  agent reasons about attachment *metadata*; it never opens an archive or an
  Office document.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class MessageFormat(StrEnum):
    """What kind of artifact was submitted for phishing analysis."""

    email_mime = "email_mime"
    """A full RFC 5322 message, normally a .eml export."""

    url = "url"
    """A bare URL or domain pasted in by an analyst, with no message around it."""


class MessageStatus(StrEnum):
    """Lifecycle of one submitted message.

    ``failed`` is terminal but retryable - it carries the reason in
    ``Message.error`` rather than silently producing a degraded verdict.
    """

    pending = "pending"
    parsing = "parsing"
    analyzing = "analyzing"
    completed = "completed"
    failed = "failed"


class MessageVerdict(StrEnum):
    """The headline answer, denormalised onto the intake row.

    Derivable from the resulting findings, but stored so a list view can render
    it without joining. Ordered least to most alarming.
    """

    clean = "clean"
    suspicious = "suspicious"
    phishing = "phishing"


class AuthResults(BaseModel):
    """SPF, DKIM and DMARC as reported by the receiving mail server.

    UNTRUSTED. These come out of an ``Authentication-Results`` header, and a
    header is just text the sender's path put there - a message that never
    touched a verifying server can claim ``spf=pass`` freely. The value is that a
    *failure* is hard to fake accidentally; a claimed pass proves nothing on its
    own. The ``enrich`` node checks the sender domain's real DNS policy
    separately.
    """

    model_config = ConfigDict(extra="forbid")

    spf: str = Field(max_length=32, description="pass|fail|softfail|neutral|none|permerror.")
    dkim: str = Field(max_length=32, description="pass|fail|none.")
    dmarc: str = Field(max_length=32, description="pass|fail|none.")
    present: bool = Field(
        description="Whether an Authentication-Results header existed at all. "
        "Absent is different from 'none' and is itself weak evidence."
    )


class EmailAddress(BaseModel):
    """One parsed address header. Every field is UNTRUSTED."""

    model_config = ConfigDict(extra="forbid")

    display_name: str = Field(
        max_length=256,
        description="UNTRUSTED. The part a mail client shows instead of the address, "
        "which is exactly why display-name spoofing works.",
    )
    address: str = Field(max_length=320, description="UNTRUSTED. Local part plus domain.")
    domain: str = Field(max_length=253, description="UNTRUSTED. Lowercased domain part.")


class EmailLink(BaseModel):
    """One link found in the body. Every field is UNTRUSTED."""

    model_config = ConfigDict(extra="forbid")

    url: str = Field(max_length=2048, description="UNTRUSTED, verbatim.")
    scheme: str = Field(max_length=16, description="UNTRUSTED.")
    host: str = Field(max_length=253, description="UNTRUSTED. Lowercased authority host.")
    anchor_text: str = Field(
        max_length=256,
        description="UNTRUSTED. The visible text of the link. A mismatch between "
        "this and `host` is one of the strongest single indicators there is.",
    )


class EmailAttachment(BaseModel):
    """Metadata for one attachment. The bytes are not carried.

    ``sha256`` is over the decoded attachment content, so an analyst can pivot to
    a threat-intel lookup without this platform ever storing or forwarding the
    file itself.
    """

    model_config = ConfigDict(extra="forbid")

    filename: str = Field(
        max_length=255,
        description="UNTRUSTED, verbatim - including any bidi override used to "
        "disguise the real extension.",
    )
    content_type: str = Field(max_length=128, description="UNTRUSTED. As declared by the sender.")
    size_bytes: int = Field(ge=0, description="Length of the decoded content.")
    sha256: str = Field(max_length=64, description="Digest of the decoded content.")


class NormalizedMessage(BaseModel):
    """A submitted artifact reduced to the shape the phishing agent reasons over."""

    model_config = ConfigDict(extra="forbid")

    format: MessageFormat
    message_id: str = Field(
        default="",
        max_length=512,
        description="UNTRUSTED. The RFC 5322 Message-ID header, not our intake id.",
    )
    subject: str = Field(default="", max_length=1024, description="UNTRUSTED.")
    date: str = Field(default="", max_length=128, description="UNTRUSTED. The Date header, verbatim.")

    sender: EmailAddress
    reply_to: EmailAddress | None = Field(default=None)
    return_path: EmailAddress | None = Field(
        default=None,
        description="The envelope sender. A mismatch with `sender` is what "
        "distinguishes a spoofed From header from a merely unusual one.",
    )
    to: list[EmailAddress] = Field(default_factory=list)

    auth: AuthResults
    received_chain: list[str] = Field(
        default_factory=list, description="UNTRUSTED. Received headers, outermost first."
    )
    headers_present: list[str] = Field(
        default_factory=list,
        description="Header names only, no values. Lets a rule notice an absent "
        "Message-ID or Received chain without carrying more untrusted text.",
    )

    body_text: str = Field(
        default="",
        description="UNTRUSTED. The text/plain part, or a tag-stripped rendering "
        "of the HTML when there is no plain part.",
    )
    body_html_present: bool = Field(
        default=False, description="Whether an HTML part existed. The markup itself is not carried."
    )

    links: list[EmailLink] = Field(default_factory=list)
    attachments: list[EmailAttachment] = Field(default_factory=list)

    @property
    def link_count(self) -> int:
        return len(self.links)

    @property
    def attachment_count(self) -> int:
        return len(self.attachments)

    @property
    def link_hosts(self) -> list[str]:
        """Distinct link hosts, in first-seen order."""
        return list(dict.fromkeys(link.host for link in self.links if link.host))
