"""Rules about who a message claims to be from.

This module exists to fix a specific defect in the previous implementation. It
collected every brand word appearing anywhere in the body, then reported
impersonation whenever one of them was absent from the sending domain. So a message
mentioning Netflix and Amazon from an unrelated sender scored two impersonation hits,
and because the old graph skipped the model once three rules fired, ordinary mail was
labelled phishing with no explanation attached.

Two changes fix it:

* **The claim has to be in the sender's identity**, not loose in the body. A display
  name of "PayPal Service" is a claim. The word "paypal" in a sentence is a topic.
* **The claim is checked against an allowlist** of the brand's real sending domains.
  ``PayPal <service@paypal.com>`` is not impersonation, and a detector that says it is
  will be switched off by the third person who sees it.
"""

from __future__ import annotations

from cyber_contracts import NormalizedMessage, Severity

from app.agents.phishing import knowledge
from app.agents.phishing.indicators import (
    Indicator,
    IndicatorCategory,
    make_indicator,
)
from app.agents.phishing.lookalike import (
    find_lookalike,
    has_punycode,
    is_mixed_script,
    registrable_domain,
)

_TECHNIQUE_WEIGHTS: dict[str, tuple[float, Severity]] = {
    # A rendered-identical domain is unambiguous - there is no honest reason to
    # register it - so it outranks a mere near-miss.
    "homoglyph": (0.90, Severity.critical),
    "punycode": (0.85, Severity.high),
    "brand-in-subdomain": (0.80, Severity.high),
    "typosquat": (0.80, Severity.high),
}


def detect(message: NormalizedMessage) -> list[Indicator]:
    """Every identity indicator this message earns."""
    found: list[Indicator] = []
    sender_domain = registrable_domain(message.sender.domain)

    found.extend(_impersonated_brand(message, sender_domain))
    found.extend(_lookalike_sender(sender_domain))
    found.extend(_deceptive_encoding(message, sender_domain))
    found.extend(_display_name_holds_an_address(message))
    return found


def _impersonated_brand(message: NormalizedMessage, sender_domain: str) -> list[Indicator]:
    """A display name claiming a brand the sending domain does not belong to."""
    # The claim is read from the sender's own identity only - display name first, then
    # the local part, since `paypal-security@evil.tld` is the same trick.
    claim_sources = (
        ("display name", message.sender.display_name),
        ("address", message.sender.address.split("@")[0] if message.sender.address else ""),
    )

    for where, text in claim_sources:
        if not text.strip():
            continue
        brand = knowledge.brand_claimed_in(text)
        if brand is None:
            continue
        # The allowlist check. Without it this rule fires on the brand's real mail.
        if sender_domain in brand.domains:
            return []

        return [
            make_indicator(
                rule_id="identity-brand-impersonation",
                category=IndicatorCategory.identity,
                locus="header:From",
                fact=(
                    f"The sender's {where} claims to be {brand.name}, but the message "
                    f"was sent from {sender_domain or 'an unknown domain'!r}, which is "
                    f"not one of {brand.name}'s sending domains."
                ),
                weight=0.85,
                severity_floor=Severity.high,
                rationale=(
                    f"{brand.name} sends its mail from a known set of domains. A "
                    "message presenting that name from anywhere else is claiming an "
                    "identity it does not have, which is the core of a phishing lure."
                ),
                evidence={
                    "claimed_brand": brand.name,
                    "claim_found_in": where,
                    "display_name": message.sender.display_name,
                    "sender": message.sender.address,
                    "sender_domain": sender_domain,
                    "legitimate_domains": sorted(brand.domains),
                },
                discriminator=brand.name,
            )
        ]

    return []


def _lookalike_sender(sender_domain: str) -> list[Indicator]:
    """A sending domain built to be mistaken for a brand's."""
    if not sender_domain:
        return []
    # If the domain genuinely belongs to a brand, find_lookalike is silent by design.
    brand_domain, technique = find_lookalike(sender_domain, knowledge.brand_domains())
    if not brand_domain:
        return []

    weight, floor = _TECHNIQUE_WEIGHTS.get(technique, (0.75, Severity.high))
    return [
        make_indicator(
            rule_id=f"identity-lookalike-{technique}",
            category=IndicatorCategory.identity,
            locus="header:From",
            fact=(
                f"The sending domain {sender_domain!r} imitates {brand_domain!r} "
                f"({technique.replace('-', ' ')})."
            ),
            weight=weight,
            severity_floor=floor,
            rationale=(
                "A domain registered to be misread as a well-known one has no "
                "legitimate use. The recipient sees the brand they expect and the mail "
                "passes its own domain's authentication, because the attacker owns it."
            ),
            evidence={
                "sender_domain": sender_domain,
                "imitates": brand_domain,
                "technique": technique,
            },
            discriminator=f"{brand_domain}|{technique}",
        )
    ]


def _deceptive_encoding(message: NormalizedMessage, sender_domain: str) -> list[Indicator]:
    """Punycode or mixed scripts in the sending domain, brand or no brand.

    Reported separately from the lookalike rule because a mixed-script domain that
    imitates nothing on the allowlist is still worth an analyst's attention - the
    brand list is short and cannot cover every organisation being impersonated.
    """
    if not sender_domain:
        return []

    found: list[Indicator] = []
    if is_mixed_script(sender_domain):
        found.append(
            make_indicator(
                rule_id="identity-mixed-script-domain",
                category=IndicatorCategory.identity,
                locus="header:From",
                fact=(
                    f"The sending domain {sender_domain!r} mixes characters from more "
                    f"than one writing system inside a single label."
                ),
                weight=0.75,
                severity_floor=Severity.high,
                rationale=(
                    "Mixing scripts within one label is how a domain is made to render "
                    "identically to an ASCII one. A genuinely non-Latin domain uses one "
                    "script consistently."
                ),
                evidence={"sender_domain": sender_domain},
            )
        )
    elif has_punycode(message.sender.domain):
        found.append(
            make_indicator(
                rule_id="identity-punycode-domain",
                category=IndicatorCategory.identity,
                locus="header:From",
                fact=(
                    f"The sending domain is punycode-encoded ({message.sender.domain!r}), "
                    f"so what a mail client displays differs from what was registered."
                ),
                weight=0.45,
                severity_floor=Severity.medium,
                rationale=(
                    "Punycode is legitimate for internationalised domains, so this is "
                    "reported rather than condemned - but it does mean the displayed "
                    "name and the real one are not the same string."
                ),
                evidence={"sender_domain": message.sender.domain},
            )
        )
    return found


def _display_name_holds_an_address(message: NormalizedMessage) -> list[Indicator]:
    """A display name that is itself an email address from another domain.

    ``"billing@paypal.com" <attacker@evil.tld>`` renders in most clients as the
    address in the display name, so the recipient reads the wrong one entirely.
    """
    display = message.sender.display_name.strip()
    if "@" not in display:
        return []

    claimed = display.strip("\"'<> ").split()[-1].strip("\"'<>")
    if "@" not in claimed:
        return []

    claimed_domain = registrable_domain(claimed.rsplit("@", 1)[-1])
    actual_domain = registrable_domain(message.sender.domain)
    if not claimed_domain or claimed_domain == actual_domain:
        return []

    return [
        make_indicator(
            rule_id="identity-display-name-is-an-address",
            category=IndicatorCategory.identity,
            locus="header:From",
            fact=(
                f"The display name is itself an email address at {claimed_domain!r}, "
                f"while the message was actually sent from {actual_domain!r}."
            ),
            weight=0.85,
            severity_floor=Severity.high,
            rationale=(
                "Most mail clients show the display name in place of the address, so "
                "putting an address there makes the client present a sender that is "
                "not the one who sent it."
            ),
            evidence={
                "display_name": message.sender.display_name,
                "claimed_domain": claimed_domain,
                "actual_sender": message.sender.address,
            },
            discriminator=claimed_domain,
        )
    ]
