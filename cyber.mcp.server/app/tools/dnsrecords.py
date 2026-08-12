"""Looking up what a domain actually publishes.

The point of this tool is narrow and specific. An ``Authentication-Results`` header
claiming ``spf=pass`` is just text that something in the delivery path wrote; a message
that never passed a verifying server carries whatever its author typed. Asking the domain's
own DNS what it publishes is the only way to tell a genuine pass from a decorative one - and
a domain that publishes no SPF record at all cannot have produced a pass.

The query set is deliberately small: SPF and DMARC because they are what the phishing rules
reason about, DKIM at the common selectors because a full selector enumeration is not
possible, and MX because a sending domain with no mail exchanger is odd.

``dnspython`` is an optional import. If it is absent the tool reports that clearly instead
of failing at module import, so the server still starts and every other tool keeps working -
enrichment is allowed to be unavailable, and a missing dependency should look like
unavailability rather than a crash.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterable
from typing import Any, Final, Protocol

# dnspython is declared in pyproject but imported defensively: the whole server should not
# fail to start because one enrichment tool's dependency is missing.
try:
    import dns.asyncresolver
    import dns.exception
    import dns.rdatatype

    DNS_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised by the absence itself
    DNS_AVAILABLE = False

TIMEOUT_SECONDS: Final = 5.0
TOTAL_TIMEOUT_SECONDS: Final = 12.0
MAX_RECORDS_PER_TYPE: Final = 10

# Selectors worth trying. DKIM selectors are chosen by the sender and cannot be enumerated
# from DNS, so this is a sample of the common ones - a miss means "we did not find one",
# never "there is none", and the tool says so.
DKIM_SELECTORS: Final[tuple[str, ...]] = (
    "default",
    "google",
    "selector1",
    "selector2",
    "s1",
    "s2",
    "k1",
    "mail",
    "dkim",
)


def _unavailable(domain: str, reason: str) -> dict[str, Any]:
    return {
        "ok": False,
        "tool": "dns_records",
        "domain": domain,
        "error": reason,
        "spf": [],
        "dmarc": [],
        "dkim_selectors_found": [],
        "mx": [],
    }


class _Resolver(Protocol):
    """The one method this module needs from a resolver.

    Narrower than `Any` so the stubbed resolver the tests inject is checked against the
    same shape the real one satisfies, and so this file states its dependency on dnspython
    as one method rather than a whole library.
    """

    async def resolve(self, qname: str, rdtype: str) -> Iterable[object]: ...


async def _query(resolver: _Resolver, name: str, record_type: str) -> list[str]:
    """One lookup, with every "no answer" outcome flattened to an empty list.

    NXDOMAIN, an empty answer and a timeout are all "we learned nothing", and the caller
    treats them the same way. Distinguishing them here would put three near-identical
    branches at every call site for no decision anyone makes differently.
    """
    try:
        answer = await resolver.resolve(name, record_type)
    except Exception:
        # Deliberately broad: dnspython raises a dozen exception types for variations of
        # "no answer", and a resolver failure must never propagate out of enrichment.
        return []

    records: list[str] = []
    for item in list(answer)[:MAX_RECORDS_PER_TYPE]:
        if record_type == "TXT":
            # A TXT record is a list of byte strings that must be concatenated; a long SPF
            # record is split across several and joining with a space would corrupt it.
            chunks = getattr(item, "strings", None)
            if chunks is not None:
                records.append(b"".join(chunks).decode("utf-8", errors="replace"))
                continue
        records.append(str(item).strip('"'))
    return records


async def lookup_dns_records(domain: str) -> dict[str, Any]:
    """Return the SPF, DMARC, DKIM and MX records ``domain`` publishes.

    Args:
        domain: A registrable domain, e.g. ``paypal.com``.

    Returns:
        A result dict. ``ok`` is False when the lookup could not be performed at all;
        finding no records is a successful lookup with empty lists, which is a meaningful
        answer rather than a failure.
    """
    cleaned = (domain or "").strip().strip(".").lower()
    if not cleaned:
        return _unavailable(domain, "No domain was supplied.")
    if not DNS_AVAILABLE:
        return _unavailable(
            cleaned,
            "dnspython is not installed on the MCP server, so DNS enrichment is "
            "unavailable. Install it to enable this tool.",
        )

    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = TIMEOUT_SECONDS
    resolver.lifetime = TIMEOUT_SECONDS

    async def gather() -> dict[str, Any]:
        root_txt, dmarc_txt, mx = await asyncio.gather(
            _query(resolver, cleaned, "TXT"),
            _query(resolver, f"_dmarc.{cleaned}", "TXT"),
            _query(resolver, cleaned, "MX"),
        )

        # Only the records that identify themselves as policies. A domain's TXT set is
        # full of unrelated verification tokens.
        spf = [record for record in root_txt if record.lower().startswith("v=spf1")]
        dmarc = [record for record in dmarc_txt if record.lower().startswith("v=dmarc1")]

        found_selectors = await asyncio.gather(
            *(
                _query(resolver, f"{selector}._domainkey.{cleaned}", "TXT")
                for selector in DKIM_SELECTORS
            )
        )
        dkim = [
            selector
            for selector, records in zip(DKIM_SELECTORS, found_selectors, strict=True)
            if records
        ]

        return {
            "ok": True,
            "tool": "dns_records",
            "domain": cleaned,
            "error": "",
            "spf": spf,
            "dmarc": dmarc,
            "dkim_selectors_found": dkim,
            "dkim_selectors_tried": list(DKIM_SELECTORS),
            "mx": mx,
            "note": (
                "DKIM selectors are chosen by the sender and cannot be enumerated, so an "
                "empty dkim_selectors_found means none of the common selectors answered - "
                "not that the domain has no DKIM."
            ),
        }

    try:
        return await asyncio.wait_for(gather(), timeout=TOTAL_TIMEOUT_SECONDS)
    except TimeoutError:
        return _unavailable(cleaned, f"DNS lookups did not finish within {TOTAL_TIMEOUT_SECONDS}s.")
    except Exception as err:  # pragma: no cover - resolver construction failures
        return _unavailable(cleaned, f"The resolver failed: {type(err).__name__}: {err}")
