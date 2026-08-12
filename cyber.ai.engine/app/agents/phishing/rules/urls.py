"""Rules about where the links actually go.

The strongest indicator in this file is the mismatch between a link's visible text and
its real host, because it is the one thing a reader cannot check without hovering. The
backend's parser preserves anchor text specifically so this rule can exist - and it
now also excludes URLs that appear *as* anchor text from the link list, so a link
labelled ``https://www.paypal.com/signin`` is recorded as one link to the attacker
with a deceptive label, not two links one of which goes to PayPal.

Nothing here fetches anything. Whether a shortener resolves somewhere hostile, and
where a redirect chain ends, is enrichment, and it goes through MCP.
"""

from __future__ import annotations

import ipaddress
from collections import Counter
from urllib.parse import urlsplit

from cyber_contracts import EmailLink, NormalizedMessage, Severity

from app.agents.phishing import knowledge
from app.agents.phishing.indicators import (
    Indicator,
    IndicatorCategory,
    make_indicator,
)
from app.agents.phishing.lookalike import find_lookalike, registrable_domain

_DANGEROUS_SCHEMES = {"javascript", "data", "vbscript", "file"}


def detect(message: NormalizedMessage) -> list[Indicator]:
    """Every URL indicator this message earns."""
    found: list[Indicator] = []
    urls = knowledge.url_knowledge()

    for position, link in enumerate(message.links):
        locus = f"link:{position}"
        found.extend(_anchor_text_mismatch(link, locus))
        found.extend(_dangerous_scheme(link, locus))
        found.extend(_ip_literal_host(link, locus))
        found.extend(_credentials_in_url(link, locus))
        found.extend(_shortener(link, locus, urls.shorteners))
        found.extend(_nonstandard_port(link, locus, urls.standard_ports))
        found.extend(_deep_subdomains(link, locus, urls.max_subdomain_labels))
        found.extend(_lookalike_host(link, locus))

    found.extend(_dominant_domain_differs_from_sender(message))
    return found


def _anchor_text_mismatch(link: EmailLink, locus: str) -> list[Indicator]:
    """Visible text naming one host while the link goes to another."""
    text = link.anchor_text.strip()
    if not text or "." not in text or not link.host:
        return []

    # Only compare when the anchor text is itself host-shaped. "Click here" is not a
    # claim about a destination, so it cannot contradict one.
    candidate = text
    if "://" in candidate:
        candidate = urlsplit(candidate).netloc or candidate
    candidate = candidate.split("/")[0].rpartition("@")[2].strip().rstrip(".")
    if candidate.count(":") == 1:
        candidate = candidate.split(":")[0]
    if " " in candidate or "@" in candidate or "." not in candidate:
        return []

    claimed = registrable_domain(candidate)
    actual = registrable_domain(link.host)
    if not claimed or not actual or claimed == actual:
        return []

    return [
        make_indicator(
            rule_id="url-anchor-text-mismatch",
            category=IndicatorCategory.url,
            locus=locus,
            fact=(
                f"A link displayed as {claimed!r} actually points to {actual!r} "
                f"({link.url})."
            ),
            weight=0.90,
            severity_floor=Severity.high,
            rationale=(
                "The recipient reads the visible text and cannot see the target "
                "without hovering. A deliberate mismatch has no legitimate purpose - "
                "it exists so the reader believes they are going somewhere else."
            ),
            evidence={"displayed": link.anchor_text, "url": link.url, "host": link.host},
            discriminator=f"{claimed}|{actual}",
        )
    ]


def _dangerous_scheme(link: EmailLink, locus: str) -> list[Indicator]:
    """``javascript:`` and ``data:`` links, which execute rather than navigate."""
    if link.scheme not in _DANGEROUS_SCHEMES:
        return []
    return [
        make_indicator(
            rule_id="url-dangerous-scheme",
            category=IndicatorCategory.url,
            locus=locus,
            fact=f"A link uses the {link.scheme}: scheme rather than http or https.",
            weight=0.85,
            severity_floor=Severity.high,
            rationale=(
                "These schemes run content or inline a document instead of navigating "
                "to a site. Legitimate mail does not use them, and some clients honour "
                "them."
            ),
            evidence={"url": link.url[:300], "scheme": link.scheme},
            discriminator=link.scheme,
        )
    ]


def _ip_literal_host(link: EmailLink, locus: str) -> list[Indicator]:
    """A link straight to an IP address."""
    if not link.host:
        return []
    try:
        ipaddress.ip_address(link.host.strip("[]"))
    except ValueError:
        return []

    return [
        make_indicator(
            rule_id="url-ip-literal-host",
            category=IndicatorCategory.url,
            locus=locus,
            fact=f"A link points directly at the IP address {link.host} rather than a domain.",
            weight=0.80,
            severity_floor=Severity.high,
            rationale=(
                "Organisations put their services behind names. A bare address in a "
                "link usually means infrastructure with no domain to lose, and it also "
                "sidesteps any reputation attached to a name."
            ),
            evidence={"url": link.url, "host": link.host},
            discriminator=link.host,
        )
    ]


def _credentials_in_url(link: EmailLink, locus: str) -> list[Indicator]:
    """``https://paypal.com@evil.tld/`` - the authority is what follows the ``@``."""
    if "://" not in link.url:
        return []
    authority = link.url.split("://", 1)[1].split("/")[0]
    if "@" not in authority:
        return []

    shown = authority.rpartition("@")[0]
    return [
        make_indicator(
            rule_id="url-credentials-in-authority",
            category=IndicatorCategory.url,
            locus=locus,
            fact=(
                f"A link is written as {shown!r}@{link.host!r}, so it reads as pointing "
                f"at {shown!r} while actually going to {link.host!r}."
            ),
            weight=0.90,
            severity_floor=Severity.high,
            rationale=(
                "Everything before the @ in a URL is user info, not the destination. "
                "It exists in the standard for authentication and is used in phishing "
                "for nothing but disguise."
            ),
            evidence={"url": link.url, "real_host": link.host, "shown_before_at": shown},
            discriminator=link.host,
        )
    ]


def _shortener(link: EmailLink, locus: str, shorteners: frozenset[str]) -> list[Indicator]:
    """A link whose destination is deliberately not visible."""
    if not link.host or registrable_domain(link.host) not in shorteners:
        return []
    return [
        make_indicator(
            rule_id="url-shortener",
            category=IndicatorCategory.url,
            locus=locus,
            fact=(
                f"A link goes through the shortener {link.host}, so its real "
                f"destination is not visible to the recipient."
            ),
            weight=0.55,
            severity_floor=Severity.medium,
            rationale=(
                "Shorteners are not malicious, they are opaque - neither the reader nor "
                "this rule can see where the link ends up. The optional link inspection "
                "can resolve it."
            ),
            evidence={"url": link.url, "shortener": link.host},
            discriminator=link.host,
        )
    ]


def _nonstandard_port(link: EmailLink, locus: str, standard: frozenset[int]) -> list[Indicator]:
    """A web link on an unusual port."""
    try:
        port = urlsplit(link.url).port
    except ValueError:
        return []  # Unparseable port; the URL itself is already evidence elsewhere.
    if port is None or port in standard:
        return []

    return [
        make_indicator(
            rule_id="url-nonstandard-port",
            category=IndicatorCategory.url,
            locus=locus,
            fact=f"A link targets port {port}, which is not a normal web port.",
            weight=0.55,
            severity_floor=Severity.medium,
            rationale=(
                "Production sites are served on the standard ports. An unusual one "
                "typically means a service stood up on borrowed or compromised "
                "infrastructure."
            ),
            evidence={"url": link.url, "port": port},
            discriminator=str(port),
        )
    ]


def _deep_subdomains(link: EmailLink, locus: str, maximum: int) -> list[Indicator]:
    """Enough labels to push the real domain out of a mail client's visible width."""
    if not link.host:
        return []
    labels = [label for label in link.host.split(".") if label]
    if len(labels) <= maximum:
        return []

    return [
        make_indicator(
            rule_id="url-excessive-subdomains",
            category=IndicatorCategory.url,
            locus=locus,
            fact=(
                f"A link host has {len(labels)} labels ({link.host}), which pushes the "
                f"registrable domain {registrable_domain(link.host)!r} to the end where "
                f"it is easy to miss."
            ),
            weight=0.50,
            severity_floor=Severity.low,
            rationale=(
                "Long label chains are used to fill the visible part of a URL with "
                "reassuring words while the domain that actually matters sits past "
                "where the reader stops looking."
            ),
            evidence={"url": link.url, "host": link.host, "labels": len(labels)},
            discriminator=link.host,
        )
    ]


def _lookalike_host(link: EmailLink, locus: str) -> list[Indicator]:
    """A link host imitating a known brand's domain."""
    if not link.host:
        return []
    brand_domain, technique = find_lookalike(link.host, knowledge.brand_domains())
    if not brand_domain:
        return []

    return [
        make_indicator(
            rule_id=f"url-lookalike-{technique}",
            category=IndicatorCategory.url,
            locus=locus,
            fact=(
                f"A link points to {link.host!r}, which imitates {brand_domain!r} "
                f"({technique.replace('-', ' ')})."
            ),
            weight=0.85,
            severity_floor=Severity.high,
            rationale=(
                "A destination built to be misread as a well-known domain is where a "
                "credential-harvesting page lives. The reader recognises the brand and "
                "the address bar agrees with them."
            ),
            evidence={"url": link.url, "host": link.host, "imitates": brand_domain,
                      "technique": technique},
            discriminator=f"{link.host}|{brand_domain}",
        )
    ]


def _dominant_domain_differs_from_sender(message: NormalizedMessage) -> list[Indicator]:
    """Where the links go, versus who the message says it is from.

    One indicator for the message rather than one per link: a newsletter linking to
    twelve partner sites is not twelve findings, and a lure whose links all go to one
    unrelated host is one fact about the message.
    """
    sender_domain = registrable_domain(message.sender.domain)
    hosts = [registrable_domain(link.host) for link in message.links if link.host]
    hosts = [host for host in hosts if host]
    if not sender_domain or not hosts:
        return []

    counts = Counter(hosts)
    dominant, dominant_count = counts.most_common(1)[0]
    if dominant == sender_domain:
        return []
    # Only when the links are overwhelmingly to one other place. A mixed set is
    # normal for real mail and says nothing.
    if dominant_count < 2 or dominant_count / len(hosts) < 0.6:
        return []

    return [
        make_indicator(
            rule_id="url-links-point-away-from-sender",
            category=IndicatorCategory.url,
            locus="message:links",
            fact=(
                f"{dominant_count} of {len(hosts)} links point to {dominant!r}, which is "
                f"unrelated to the sending domain {sender_domain!r}."
            ),
            weight=0.50,
            severity_floor=Severity.low,
            rationale=(
                "A message from one organisation whose links almost all go to another "
                "is either a forwarded lure or a sender that is not who it claims. Weak "
                "alone, because bulk senders legitimately use separate link domains."
            ),
            evidence={
                "sender_domain": sender_domain,
                "dominant_link_domain": dominant,
                "link_domains": dict(counts),
            },
            discriminator=dominant,
        )
    ]
