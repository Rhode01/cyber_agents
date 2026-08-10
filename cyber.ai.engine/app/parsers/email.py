"""MIME email parser for the phishing detection agent.

Parses raw MIME email (RFC 2822 / RFC 5322) and extracts all fields the
phishing agent uses for rule-based and LLM-assisted detection.

Example::

    email = parse(raw_mime)
    print(email.sender, email.reply_to, email.links)
    print(email.spf_result, email.dkim_result, email.dmarc_result)
"""

from __future__ import annotations

import email as _email_lib
import email.policy
import html
import re
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Any

from app.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class ParsedEmail:
    # ---- envelope / headers -------------------------------------------------
    message_id: str
    subject: str
    sender: str             # From: header
    sender_domain: str      # domain part of From
    display_name: str       # display name from From header (may differ from domain)
    reply_to: str           # Reply-To header (empty string if not present)
    reply_to_domain: str
    to: list[str]
    date: str

    # ---- authentication results (from Authentication-Results header) --------
    spf_result: str         # pass / fail / softfail / neutral / none / permerror
    dkim_result: str        # pass / fail / none
    dmarc_result: str       # pass / fail / none

    # ---- body ---------------------------------------------------------------
    plain_text: str
    html_text: str
    links: list[str]        # all hrefs extracted from HTML + plain text URLs
    link_domains: list[str] # unique domains from links

    # ---- attachments --------------------------------------------------------
    attachments: list[dict[str, Any]]  # {filename, content_type, size_bytes}

    # ---- indicators ---------------------------------------------------------
    urgency_phrases: list[str]   # matched urgency keywords
    brand_keywords: list[str]    # impersonated brand names detected


# ---- Regex helpers ----------------------------------------------------------

_URL_RE = re.compile(
    r"https?://[^\s\"'<>\]\)]+",
    re.IGNORECASE,
)

_HREF_RE = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)

_DOMAIN_RE = re.compile(r"https?://([^/\s?#]+)")

_AUTH_RESULT_RE = re.compile(
    r"(spf|dkim|dmarc)\s*=\s*(\w+)", re.IGNORECASE
)

_URGENCY_PHRASES = [
    "act now", "immediate action", "account suspended", "verify your account",
    "confirm your identity", "click here immediately", "limited time",
    "unusual activity", "unauthorized access", "your account will be",
    "update your information", "your password", "security alert",
    "invoice attached", "payment required", "overdue", "unpaid",
    "click to confirm", "failure to act", "within 24 hours", "within 48 hours",
]

_BRAND_KEYWORDS = [
    "paypal", "apple", "microsoft", "amazon", "google", "facebook", "instagram",
    "netflix", "linkedin", "dropbox", "docusign", "fedex", "ups", "dhl",
    "irs", "hmrc", "chase", "wells fargo", "bank of america", "citibank",
    "stripe", "shopify", "twitter", "whatsapp",
]


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def parse(raw: str) -> ParsedEmail:
    """Parse a raw MIME email string and return a ``ParsedEmail``."""
    msg: EmailMessage = _email_lib.message_from_string(
        raw, policy=email.policy.default
    )

    # ---- Headers ------------------------------------------------------------
    message_id = _header(msg, "Message-ID")
    subject = _header(msg, "Subject")
    from_raw = _header(msg, "From")
    sender, sender_domain, display_name = _parse_address(from_raw)

    reply_to_raw = _header(msg, "Reply-To")
    reply_to, reply_to_domain, _ = _parse_address(reply_to_raw)

    to_raw = _header(msg, "To")
    to_list = [a.strip() for a in to_raw.split(",") if a.strip()]

    date = _header(msg, "Date")

    # ---- Authentication-Results --------------------------------------------
    auth_results = _header(msg, "Authentication-Results")
    spf, dkim, dmarc = _parse_auth_results(auth_results)

    # ---- Body ---------------------------------------------------------------
    plain_text = ""
    html_text = ""

    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            charset = part.get_content_charset() or "utf-8"
            try:
                payload = part.get_payload(decode=True)
                if payload is None:
                    continue
                if isinstance(payload, bytes):
                    text = payload.decode(charset, errors="replace")
                else:
                    text = str(payload)
            except Exception as exc:
                logger.warning("email.part_decode_failed", error=str(exc))
                continue
            if ct == "text/plain" and not plain_text:
                plain_text = text
            elif ct == "text/html" and not html_text:
                html_text = text
    else:
        ct = msg.get_content_type()
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or "utf-8"
                if isinstance(payload, bytes):
                    text = payload.decode(charset, errors="replace")
                else:
                    text = str(payload)
                if ct == "text/html":
                    html_text = text
                else:
                    plain_text = text
        except Exception as exc:
            logger.warning("email.body_decode_failed", error=str(exc))

    # ---- Links --------------------------------------------------------------
    links: list[str] = []
    if html_text:
        links += _HREF_RE.findall(html_text)
        # Also catch plain-text URLs inside HTML
        links += _URL_RE.findall(html.unescape(html_text))
    if plain_text:
        links += _URL_RE.findall(plain_text)

    # Deduplicate while preserving order
    seen: set[str] = set()
    unique_links: list[str] = []
    for link in links:
        if link not in seen:
            seen.add(link)
            unique_links.append(link)

    link_domains: list[str] = []
    seen_domains: set[str] = set()
    for link in unique_links:
        m = _DOMAIN_RE.match(link)
        if m:
            d = m.group(1).lower()
            if d not in seen_domains:
                seen_domains.add(d)
                link_domains.append(d)

    # ---- Attachments --------------------------------------------------------
    attachments: list[dict[str, Any]] = []
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_disposition() == "attachment":
                payload = part.get_payload(decode=True) or b""
                attachments.append({
                    "filename": part.get_filename() or "",
                    "content_type": part.get_content_type(),
                    "size_bytes": len(payload),
                })

    # ---- Indicators ---------------------------------------------------------
    body_lower = (plain_text + " " + html_text).lower()
    urgency_phrases = [p for p in _URGENCY_PHRASES if p in body_lower]
    full_lower = (subject + " " + body_lower + " " + from_raw).lower()
    brand_keywords = [b for b in _BRAND_KEYWORDS if b in full_lower]

    return ParsedEmail(
        message_id=message_id,
        subject=subject,
        sender=sender,
        sender_domain=sender_domain,
        display_name=display_name,
        reply_to=reply_to,
        reply_to_domain=reply_to_domain,
        to=to_list,
        date=date,
        spf_result=spf,
        dkim_result=dkim,
        dmarc_result=dmarc,
        plain_text=plain_text,
        html_text=html_text,
        links=unique_links,
        link_domains=link_domains,
        attachments=attachments,
        urgency_phrases=urgency_phrases,
        brand_keywords=brand_keywords,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _header(msg: EmailMessage, name: str) -> str:
    val = msg.get(name, "")
    return str(val).strip() if val else ""


def _parse_address(raw: str) -> tuple[str, str, str]:
    """Return (email_address, domain, display_name) from a header value."""
    if not raw:
        return "", "", ""

    # "Display Name <email@domain.com>"
    m = re.match(r'^"?([^"<]*)"?\s*<([^>]+)>', raw.strip())
    if m:
        display_name = m.group(1).strip().strip('"')
        addr = m.group(2).strip()
    else:
        display_name = ""
        addr = raw.strip()

    # Extract domain
    at = addr.rfind("@")
    domain = addr[at + 1:].lower() if at != -1 else ""
    return addr, domain, display_name


def _parse_auth_results(raw: str) -> tuple[str, str, str]:
    """Extract SPF, DKIM, DMARC results from Authentication-Results header."""
    spf = dkim = dmarc = "none"
    for m in _AUTH_RESULT_RE.finditer(raw):
        proto = m.group(1).lower()
        result = m.group(2).lower()
        if proto == "spf":
            spf = result
        elif proto == "dkim":
            dkim = result
        elif proto == "dmarc":
            dmarc = result
    return spf, dkim, dmarc
