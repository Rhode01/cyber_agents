"""Fetching a link out of a hostile message, as safely as this can be done.

This is the only thing in the platform that deliberately contacts a host chosen by an
attacker, so the constraints are worth stating plainly.

**Redirects are followed by hand.** ``follow_redirects=False``, and each hop goes back
through ``check_fetch_target`` before it is requested. Letting the client follow them would
check only the first URL - and a redirect is precisely how a public-looking link reaches
``169.254.169.254``, the cloud metadata endpoint, and reads this host's own credentials.
The previous implementation used ``curl -s -L``, which followed every hop unchecked.

**Nothing is executed or rendered.** The body is parsed with regular expressions for four
structural facts: the title, whether a password input exists, where any form submits, and a
prefix of the visible text. No HTML parser, no JavaScript, no images fetched, no headless
browser. "Does this look like a login page" is answered structurally, because rendering an
attacker's page to look at it is a strange way to stay safe.

**Everything is bounded.** Hops, body size, total time, and the response headers we keep. A
page that streams forever gets ``MAX_BODY_BYTES`` and no more.

**Residual risk, named rather than papered over.** ``check_fetch_target`` resolves the
host, then httpx resolves it again when it connects. Between those two moments the answer
can change - DNS rebinding. Closing it means pinning the connection to the vetted address
while still sending the right ``Host`` header and TLS SNI, which needs a custom transport.
For now the per-hop check plus the hop cap is the mitigation, and this paragraph is the
disclosure.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Final

import httpx

from app.tools.targets import check_fetch_target

MAX_HOPS: Final = 5
MAX_BODY_BYTES: Final = 512_000
TIMEOUT_SECONDS: Final = 10.0
VISIBLE_TEXT_CHARS: Final = 600

# A browser-ish user agent. Not to hide - a phishing site that serves different content to
# obvious automation would otherwise show us a blank page, and the point is to see what a
# recipient would see.
USER_AGENT: Final = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0 Safari/537.36"
)

_TITLE_RE: Final = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_PASSWORD_RE: Final = re.compile(
    r"""<input\b[^>]*\btype\s*=\s*["']?password["']?""", re.IGNORECASE
)
_FORM_ACTION_RE: Final = re.compile(
    r"""<form\b[^>]*\baction\s*=\s*["']([^"']*)["']""", re.IGNORECASE
)
_TAG_RE: Final = re.compile(r"<[^>]{0,4096}>")
_SCRIPT_RE: Final = re.compile(r"<(script|style|head)\b.*?</\1\s*>", re.IGNORECASE | re.DOTALL)
_WHITESPACE_RE: Final = re.compile(r"\s+")


@dataclass(slots=True)
class FetchOutcome:
    """What one fetch learned, or why it did not happen."""

    ok: bool
    url: str
    final_url: str = ""
    final_host: str = ""
    status: int | None = None
    redirect_chain: list[str] = field(default_factory=list)
    title: str = ""
    password_field: bool = False
    form_hosts: list[str] = field(default_factory=list)
    visible_text: str = ""
    bytes_read: int = 0
    truncated: bool = False
    error: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "url": self.url,
            "final_url": self.final_url,
            "final_host": self.final_host,
            "status": self.status,
            "redirect_chain": self.redirect_chain,
            "title": self.title,
            "password_field": self.password_field,
            "form_hosts": self.form_hosts,
            "visible_text": self.visible_text,
            "bytes_read": self.bytes_read,
            "truncated": self.truncated,
            "error": self.error,
        }


def _host_of(url: str) -> str:
    from urllib.parse import urlparse

    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def _extract(body: str) -> tuple[str, bool, list[str], str]:
    """Pull the four structural facts out of a page body.

    Regex rather than a parser, on purpose: a parser is more code handling
    attacker-authored markup, for output that only ever gets read as prose.
    """
    title_match = _TITLE_RE.search(body)
    title = ""
    if title_match:
        title = _WHITESPACE_RE.sub(" ", _TAG_RE.sub("", title_match.group(1))).strip()[:200]

    password_field = _PASSWORD_RE.search(body) is not None

    form_hosts: list[str] = []
    for action in _FORM_ACTION_RE.findall(body):
        host = _host_of(action)
        # A relative action posts back to the page itself, which is not a separate fact.
        if host and host not in form_hosts:
            form_hosts.append(host)

    visible = _WHITESPACE_RE.sub(" ", _TAG_RE.sub(" ", _SCRIPT_RE.sub(" ", body))).strip()
    return title, password_field, form_hosts[:10], visible[:VISIBLE_TEXT_CHARS]


async def _read_capped(response: httpx.Response) -> tuple[str, int, bool]:
    """Read at most ``MAX_BODY_BYTES``, then stop.

    Streamed so a page that never ends costs a fixed amount rather than all available
    memory. Decoded latin-1 because the extraction below only looks for ASCII markup and
    latin-1 cannot raise - a charset guess that failed would lose the whole body.
    """
    chunks: list[bytes] = []
    total = 0
    truncated = False
    async for chunk in response.aiter_bytes():
        remaining = MAX_BODY_BYTES - total
        if len(chunk) >= remaining:
            chunks.append(chunk[:remaining])
            total += remaining
            truncated = True
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks).decode("latin-1", errors="replace"), total, truncated


async def fetch_page(url: str) -> FetchOutcome:
    """Follow ``url``, checking every hop, and report what the destination is.

    Args:
        url: An absolute http or https URL, from an untrusted message.

    Returns:
        A ``FetchOutcome``. ``ok`` is False for a refused target, a transport failure or a
        hop cap - the reason is always in ``error``, never an exception, because this runs
        inside enrichment where a failure must cost detail and nothing else.
    """
    outcome = FetchOutcome(ok=False, url=url)
    current = url

    try:
        async with httpx.AsyncClient(
            follow_redirects=False,  # every hop is checked by hand below
            timeout=httpx.Timeout(TIMEOUT_SECONDS),
            headers={"user-agent": USER_AGENT, "accept": "text/html,*/*"},
            # No cookie jar and no credential store: nothing this server holds should be
            # offered to a host named by a phishing email.
            cookies=None,
            trust_env=False,  # ignore proxy env vars, which could route us anywhere
        ) as client:
            for hop in range(MAX_HOPS + 1):
                decision = await check_fetch_target(current)
                if not decision.allowed:
                    outcome.error = decision.reason
                    outcome.final_url = current
                    outcome.final_host = decision.host
                    return outcome

                outcome.redirect_chain.append(decision.host)

                response = await client.send(
                    client.build_request("GET", current), stream=True
                )
                try:
                    outcome.status = response.status_code
                    location = response.headers.get("location")

                    if response.is_redirect and location:
                        if hop >= MAX_HOPS:
                            outcome.error = (
                                f"Stopped after {MAX_HOPS} redirects without reaching a "
                                f"final page."
                            )
                            outcome.final_url = current
                            outcome.final_host = decision.host
                            return outcome
                        # Resolve relative Location headers against the current URL.
                        current = str(httpx.URL(current).join(location))
                        continue

                    body, read, truncated = await _read_capped(response)
                finally:
                    await response.aclose()

                title, password_field, form_hosts, visible = _extract(body)
                outcome.ok = True
                outcome.final_url = current
                outcome.final_host = decision.host
                outcome.title = title
                outcome.password_field = password_field
                outcome.form_hosts = form_hosts
                outcome.visible_text = visible
                outcome.bytes_read = read
                outcome.truncated = truncated
                return outcome

    except httpx.HTTPError as err:
        outcome.error = f"{type(err).__name__}: {err}"
        outcome.final_url = current
        return outcome

    # Only reachable if MAX_HOPS is misconfigured to a negative number.
    outcome.error = "The fetch ended without a response."
    return outcome
