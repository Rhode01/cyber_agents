"""RFC 5322 message parser.

Parsing lives in the backend for the same reason Nmap parsing does: the backend
owns the raw artifact, and what crosses the wire is the normalized form. The
ai.engine reasons over ``NormalizedMessage`` and never sees the original bytes.

Four properties matter more than completeness:

1. **The input is hostile, and hostile in a way scanner output is not.** A
   phishing email is a document written specifically to manipulate whoever reads
   it, and downstream of this parser the reader is a language model. Every
   collection is bounded and every string is length-capped.

2. **Nothing is sanitised.** Subjects, display names, anchor text and attachment
   filenames are carried through as-is, including any bidi override or homoglyph.
   Stripping them here would destroy the evidence the lookalike and injection
   rules exist to find, and would imply a safety that does not hold. Fencing
   happens exactly once, at the prompt boundary, in the ai.engine.

   One documented exception, and it is the stdlib's rather than ours: a header
   containing raw 8-bit bytes that are **not** valid UTF-8 comes back with U+FFFD
   in place of those bytes, because ``email.policy.default`` decodes headers as
   UTF-8. Properly encoded headers are unaffected, which covers the cases that
   matter here - RFC 2047 encoded words and 8-bit UTF-8 both round-trip, so a
   Cyrillic homoglyph in a From header survives intact. Only genuinely malformed
   latin-1 headers degrade, and they degrade visibly rather than silently.

3. **Parsing is from bytes, not str.** ``email.message_from_bytes`` lets the
   stdlib resolve each part's own charset. Real ``.eml`` files are frequently not
   valid UTF-8 - a quoted-printable latin-1 body is entirely ordinary - so the
   strict-UTF-8 rule the scan intake applies would reject legitimate mail.

4. **Two things are deliberately dropped.** The raw HTML body is never carried
   (only its text rendering, its links, and a flag saying it existed), and
   attachment *bytes* are hashed and discarded. Neither is needed downstream, and
   what is never carried can never leak into a prompt or a browser.
"""

from __future__ import annotations

import email
import email.message
import email.policy
import email.utils
import hashlib
import re
from email.message import EmailMessage
from typing import Final

from cyber_contracts import (
    AuthResults,
    EmailAddress,
    EmailAttachment,
    EmailLink,
    MessageFormat,
    NormalizedMessage,
)

from app.services.ingestion.errors import ScanParseError

# Bounds. Exceeding one raises rather than truncating, so a stored message never
# silently represents only part of what was submitted - the same stance the Nmap
# parser takes about host and port counts.
MAX_PARTS: Final = 64
MAX_LINKS: Final = 200
MAX_ATTACHMENTS: Final = 32
MAX_RECEIVED: Final = 32
MAX_RECIPIENTS: Final = 64
MAX_BODY_CHARS: Final = 40_000

# Field caps mirror the contract's max_length, so an absurd header is clipped
# here rather than failing validation after the whole message has been walked.
_DISPLAY_NAME_MAX: Final = 256
_ADDRESS_MAX: Final = 320
_DOMAIN_MAX: Final = 253
_SUBJECT_MAX: Final = 1024
_MESSAGE_ID_MAX: Final = 512
_DATE_MAX: Final = 128
_URL_MAX: Final = 2048
_ANCHOR_MAX: Final = 256
_FILENAME_MAX: Final = 255
_CONTENT_TYPE_MAX: Final = 128
_RECEIVED_MAX: Final = 998  # RFC 5322 line-length ceiling
_AUTH_RESULT_MAX: Final = 32

# `href="..."` together with the anchor text that follows it. Non-greedy and
# bounded by the closing tag so one unterminated anchor cannot swallow the body.
_ANCHOR_RE: Final = re.compile(
    r"<a\b[^>]*?href\s*=\s*(?P<quote>[\"'])(?P<url>.*?)(?P=quote)[^>]*>(?P<text>.*?)</a\s*>",
    re.IGNORECASE | re.DOTALL,
)
# A bare href, for links whose anchor never closes or which sit on other tags.
_HREF_RE: Final = re.compile(
    r"""(?:href|src|action)\s*=\s*(?P<quote>["'])(?P<url>.*?)(?P=quote)""", re.IGNORECASE
)
_PLAIN_URL_RE: Final = re.compile(r"""[a-z][a-z0-9+.\-]{1,15}://[^\s"'<>)\]}]+""", re.IGNORECASE)
# RFC 3986 scheme production, anchored, so "C:\path" and "foo bar:baz" are not
# mistaken for URLs while "https:" and "javascript:" are recognised.
_SCHEME_RE: Final = re.compile(r"([a-z][a-z0-9+.\-]{0,15}):", re.IGNORECASE)
_TAG_RE: Final = re.compile(r"<[^>]{0,4096}>")
_WHITESPACE_RE: Final = re.compile(r"[ \t\r\f\v]+")
_AUTH_PAIR_RE: Final = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.IGNORECASE)


def _clip(value: str | None, limit: int) -> str:
    """Trim an untrusted string to its contract length. Never returns None.

    Header absence and an empty header are the same thing to every rule that
    consumes this, so both become "".
    """
    if not value:
        return ""
    return value.strip()[:limit]


def _domain_of(address: str) -> str:
    """The domain part of an address, lowercased. "" when there isn't one."""
    _, _, domain = address.rpartition("@")
    return domain.strip().strip(">").lower()[:_DOMAIN_MAX]


def _parse_address(raw: str) -> EmailAddress:
    """Split one address header into display name, address and domain.

    Uses ``email.utils.parseaddr`` rather than a regex: it already implements the
    quoting and comment rules that make hand-rolled parsing of these headers
    wrong in ways an attacker can choose.
    """
    display_name, address = email.utils.parseaddr(raw or "")
    return EmailAddress(
        display_name=_clip(display_name, _DISPLAY_NAME_MAX),
        address=_clip(address, _ADDRESS_MAX),
        domain=_domain_of(address),
    )


def _header(message: EmailMessage, name: str) -> str:
    """One header as a plain string, with decoding failures degraded not raised.

    A malformed encoded-word raises inside the policy's header parser. That is a
    property of the message, not a bug here, so the raw value is used instead -
    losing the decoding but keeping the evidence.
    """
    try:
        value = message.get(name)
    except (ValueError, IndexError, LookupError, UnicodeDecodeError):
        return ""
    if value is None:
        return ""
    return str(value).replace("\n", " ").replace("\r", " ")


def _parse_auth_results(raw: str) -> AuthResults:
    """Read SPF/DKIM/DMARC out of an Authentication-Results header.

    Only the *first* occurrence of each method is taken. A crafted header can
    append ``spf=pass`` after a genuine ``spf=fail``, and reading left to right
    means the receiving server's own verdict wins over anything appended later.
    """
    found: dict[str, str] = {}
    for match in _AUTH_PAIR_RE.finditer(raw):
        method = match.group(1).lower()
        if method not in found:
            found[method] = match.group(2).lower()[:_AUTH_RESULT_MAX]

    return AuthResults(
        spf=found.get("spf", "none"),
        dkim=found.get("dkim", "none"),
        dmarc=found.get("dmarc", "none"),
        present=bool(raw.strip()),
    )


def _strip_tags(html: str) -> str:
    """Render HTML down to its visible text.

    Deliberately crude - no HTML parser, no entity resolution beyond the common
    few. The output is only ever read as prose by a rule or a model, so a missed
    tag costs a little noise. Bringing in a real parser would mean handing
    attacker-authored markup to more code, for no gain.
    """
    without_invisible = re.sub(
        r"<(script|style|head)\b.*?</\1\s*>", " ", html, flags=re.IGNORECASE | re.DOTALL
    )
    text = _TAG_RE.sub(" ", without_invisible)
    for entity, char in (
        ("&nbsp;", " "),
        ("&amp;", "&"),
        ("&lt;", "<"),
        ("&gt;", ">"),
        ("&quot;", '"'),
        ("&#39;", "'"),
    ):
        text = text.replace(entity, char)
    return _WHITESPACE_RE.sub(" ", text)


def _link_of(url: str, anchor_text: str) -> EmailLink | None:
    """Build one link, or None when there is no usable URL.

    ``urlsplit`` is avoided for the host: it raises on some malformed authorities,
    and a malformed authority is itself a signal we want to keep rather than a
    reason to discard the link. The split below is lenient on purpose.
    """
    cleaned = url.strip()
    if not cleaned or cleaned.startswith("#"):
        return None

    scheme_match = _SCHEME_RE.match(cleaned)
    if scheme_match is not None:
        scheme = scheme_match.group(1)
        remainder = cleaned[scheme_match.end() :]
    elif cleaned.startswith("//"):
        # Protocol-relative. Worth keeping: the host is still the thing rules care
        # about, and mail clients resolve these.
        scheme, remainder = "", cleaned
    else:
        # Relative path, mailto:, or junk. No host to reason about.
        return None

    if remainder.startswith("//"):
        authority = remainder[2:].split("/")[0].split("?")[0].split("#")[0]
        # Strip userinfo but record nothing here: the `paypal.com@evil.tld` trick
        # is detected by a rule reading `url`, which stays verbatim.
        if "@" in authority:
            authority = authority.rpartition("@")[2]
        host = authority.rsplit(":", 1)[0] if authority.count(":") == 1 else authority
        host = host.strip("[]").lower()[:_DOMAIN_MAX]
    else:
        # An opaque scheme - mailto:, javascript:, data:, tel:. There is no network
        # authority, so there is no host. Kept rather than dropped, with host "",
        # because `javascript:` and `data:` are themselves worth flagging; giving
        # them the local part of an address as a "host" would instead invent a
        # destination the message never had.
        host = ""

    return EmailLink(
        url=cleaned[:_URL_MAX],
        scheme=scheme.lower()[:16],
        host=host,
        anchor_text=_clip(_strip_tags(anchor_text), _ANCHOR_MAX),
    )


def _extract_links(html: str, text: str) -> list[EmailLink]:
    """Collect the links a recipient could actually follow.

    Order matters, and so does what is excluded.

    Anchors are read **first** so ``anchor_text`` is populated wherever it exists.
    The mismatch between the visible text and the real host is one of the
    strongest single indicators there is, and it only exists for anchors, so a
    later bare-href match for the same URL must not be allowed to overwrite it -
    hence deduplication on the URL alone, first occurrence winning.

    Anchor *elements* are then removed before scanning the HTML for bare URLs.
    Without that, a link whose visible text is itself a URL - the classic
    ``<a href="http://45.61.188.203/...">https://www.paypal.com/signin</a>`` -
    yields a phantom link to the impersonated domain. That is not a link the
    message contains; recording it would invent a "links to PayPal" signal and
    could mask the real destination. The visible text is already preserved on the
    genuine link as ``anchor_text``, which is where the rules look for it.
    """
    links: list[EmailLink] = []
    seen: set[str] = set()

    def add(candidate: EmailLink | None) -> None:
        if candidate is None or candidate.url in seen:
            return
        seen.add(candidate.url)
        links.append(candidate)

    for match in _ANCHOR_RE.finditer(html):
        add(_link_of(match.group("url"), match.group("text")))
    for match in _HREF_RE.finditer(html):
        add(_link_of(match.group("url"), ""))

    html_without_anchors = _ANCHOR_RE.sub(" ", html)
    for source in (text, _strip_tags(html_without_anchors)):
        for match in _PLAIN_URL_RE.finditer(source):
            add(_link_of(match.group(0), ""))

    if len(links) > MAX_LINKS:
        msg = f"message contains more than {MAX_LINKS} links ({len(links)})"
        raise ScanParseError(msg)
    return links


def _decode_part(part: EmailMessage) -> str:
    """One part's payload as text, with its declared charset honoured."""
    try:
        payload = part.get_payload(decode=True)
    except (ValueError, LookupError, AssertionError):
        return ""
    if not isinstance(payload, bytes):
        return ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except LookupError:
        # A charset name the sender invented. latin-1 cannot fail and keeps the
        # bytes recoverable, which matters because this text becomes evidence.
        return payload.decode("latin-1", errors="replace")


def parse_email_mime(raw: bytes) -> NormalizedMessage:
    """Parse a MIME message into the shape the phishing agent reasons over.

    Args:
        raw: The submitted bytes, exactly as uploaded.

    Returns:
        A ``NormalizedMessage``. Untrusted values are carried verbatim.

    Raises:
        ScanParseError: unparseable, or past one of the bounds above.
    """
    if not raw.strip():
        msg = "the submitted message is empty"
        raise ScanParseError(msg)

    try:
        parsed = email.message_from_bytes(raw, policy=email.policy.default)
    except (ValueError, IndexError, LookupError) as err:
        msg = f"could not parse the message: {err}"
        raise ScanParseError(msg) from err

    if not isinstance(parsed, EmailMessage):  # pragma: no cover - policy.default guarantees it
        msg = "the message did not parse to an EmailMessage"
        raise ScanParseError(msg)

    headers_present = sorted({name.lower() for name, _ in parsed.items()})
    if "from" not in headers_present and "received" not in headers_present:
        # Neither an author nor a delivery path. Rejected rather than analysed as
        # an anonymous blank: a rule engine given no sender produces confident
        # nonsense, and a 415 at the API is more useful than that.
        msg = "not an email message: no From or Received header"
        raise ScanParseError(msg)

    plain_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[EmailAttachment] = []
    part_count = 0

    for part in parsed.walk():
        part_count += 1
        if part_count > MAX_PARTS:
            msg = f"message has more than {MAX_PARTS} MIME parts"
            raise ScanParseError(msg)
        if not isinstance(part, EmailMessage) or part.get_content_maintype() == "multipart":
            continue

        if part.get_content_disposition() == "attachment":
            if len(attachments) >= MAX_ATTACHMENTS:
                msg = f"message has more than {MAX_ATTACHMENTS} attachments"
                raise ScanParseError(msg)
            try:
                content = part.get_payload(decode=True)
            except (ValueError, LookupError, AssertionError):
                content = b""
            body = content if isinstance(content, bytes) else b""
            attachments.append(
                EmailAttachment(
                    filename=_clip(part.get_filename(), _FILENAME_MAX),
                    content_type=_clip(part.get_content_type(), _CONTENT_TYPE_MAX),
                    size_bytes=len(body),
                    # Hashed here and then dropped. Nothing downstream of this
                    # function can be handed attachment content, because nothing
                    # downstream is given it.
                    sha256=hashlib.sha256(body).hexdigest(),
                )
            )
            continue

        content_type = part.get_content_type()
        if content_type == "text/plain":
            plain_parts.append(_decode_part(part))
        elif content_type == "text/html":
            html_parts.append(_decode_part(part))

    html = "\n".join(html_parts)
    plain = "\n".join(plain_parts)

    # An HTML-only message still needs readable prose for the tone and urgency
    # rules, so the markup is rendered down. `body_html_present` records which of
    # the two happened, because "HTML only" is itself weakly suspicious.
    body_text = plain if plain.strip() else _strip_tags(html)
    if len(body_text) > MAX_BODY_CHARS:
        msg = f"message body exceeds {MAX_BODY_CHARS} characters ({len(body_text)})"
        raise ScanParseError(msg)

    received = [_clip(value, _RECEIVED_MAX) for value in parsed.get_all("Received", [])]
    if len(received) > MAX_RECEIVED:
        msg = f"message has more than {MAX_RECEIVED} Received headers ({len(received)})"
        raise ScanParseError(msg)

    recipients: list[EmailAddress] = []
    for display_name, address in email.utils.getaddresses([_header(parsed, "To")]):
        if not (display_name.strip() or address.strip()):
            continue
        recipients.append(
            EmailAddress(
                display_name=_clip(display_name, _DISPLAY_NAME_MAX),
                address=_clip(address, _ADDRESS_MAX),
                domain=_domain_of(address),
            )
        )
        if len(recipients) >= MAX_RECIPIENTS:
            break

    reply_to_raw = _header(parsed, "Reply-To")
    return_path_raw = _header(parsed, "Return-Path")

    return NormalizedMessage(
        format=MessageFormat.email_mime,
        message_id=_clip(_header(parsed, "Message-ID"), _MESSAGE_ID_MAX),
        subject=_clip(_header(parsed, "Subject"), _SUBJECT_MAX),
        date=_clip(_header(parsed, "Date"), _DATE_MAX),
        sender=_parse_address(_header(parsed, "From")),
        reply_to=_parse_address(reply_to_raw) if reply_to_raw.strip() else None,
        return_path=_parse_address(return_path_raw) if return_path_raw.strip() else None,
        to=recipients,
        auth=_parse_auth_results(_header(parsed, "Authentication-Results")),
        received_chain=received,
        headers_present=headers_present,
        body_text=body_text,
        body_html_present=bool(html.strip()),
        links=_extract_links(html, plain),
        attachments=attachments,
    )
