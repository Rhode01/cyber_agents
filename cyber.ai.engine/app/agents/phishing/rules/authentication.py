"""Rules over the headers that say who sent a message.

These are the strongest indicators in the whole engine, and the reason is worth
stating: SPF, DKIM and DMARC are the only signals here that a *receiving server*
produced rather than the sender. Everything else in a message is the sender's own
text. So a failure is close to fact, while a pass proves very little - anyone can put
``spf=pass`` in a header they wrote, and a message that never passed through a
verifying server carries whatever its author typed.

Hence the asymmetry throughout: failures score heavily, and a claimed pass is treated
as nothing more than the absence of a failure. The ``enrich`` step checks the sender
domain's real published policy separately, over MCP, which is the only way to tell a
genuine pass from a decorative one.
"""

from __future__ import annotations

from cyber_contracts import NormalizedMessage, Severity

from app.agents.phishing.indicators import (
    Indicator,
    IndicatorCategory,
    make_indicator,
)
from app.agents.phishing.lookalike import registrable_domain

# Results that mean "this failed", as opposed to "nothing was checked".
_SPF_FAILURES = {"fail", "softfail", "permerror", "temperror"}
_HARD_FAILURES = {"fail"}


def detect(message: NormalizedMessage) -> list[Indicator]:
    """Every authentication indicator this message earns."""
    found: list[Indicator] = []
    auth = message.auth

    if auth.spf in _SPF_FAILURES:
        # softfail is separated out because it means "probably not authorised" rather
        # than "definitely not", and a domain mid-migration produces it legitimately.
        hard = auth.spf in _HARD_FAILURES
        found.append(
            make_indicator(
                rule_id="auth-spf-failed",
                category=IndicatorCategory.authentication,
                locus="header:Authentication-Results",
                fact=(
                    f"SPF returned '{auth.spf}': the sending server is not authorised "
                    f"to send mail for the sender's domain."
                ),
                weight=0.85 if hard else 0.55,
                severity_floor=Severity.high if hard else Severity.medium,
                rationale=(
                    "SPF is checked by the receiving server against a record the "
                    "domain owner publishes, so a failure is one of the few facts in "
                    "a message the sender could not simply write."
                ),
                evidence={"spf": auth.spf},
                discriminator=auth.spf,
            )
        )

    if auth.dkim in _HARD_FAILURES:
        found.append(
            make_indicator(
                rule_id="auth-dkim-failed",
                category=IndicatorCategory.authentication,
                locus="header:Authentication-Results",
                fact=(
                    "DKIM signature validation failed: the message body or headers "
                    "were altered after signing, or the signature does not belong to "
                    "the sending domain."
                ),
                weight=0.80,
                severity_floor=Severity.high,
                rationale=(
                    "A DKIM failure means the cryptographic signature does not match "
                    "the content, which legitimate mail flows do not normally produce."
                ),
                evidence={"dkim": auth.dkim},
            )
        )

    if auth.dmarc in _HARD_FAILURES:
        found.append(
            make_indicator(
                rule_id="auth-dmarc-failed",
                category=IndicatorCategory.authentication,
                locus="header:Authentication-Results",
                fact=(
                    "DMARC failed: neither SPF nor DKIM aligned with the domain in the "
                    "From header, which is the check specifically designed to catch "
                    "sender spoofing."
                ),
                weight=0.90,
                severity_floor=Severity.high,
                rationale=(
                    "DMARC alignment exists to answer exactly one question - is the "
                    "From header honest - so a failure is the most direct evidence of "
                    "spoofing available in a message."
                ),
                evidence={"dmarc": auth.dmarc},
            )
        )

    if not auth.present:
        # Absent is different from "none", and much weaker than a failure: a saved
        # draft or an API export legitimately has no Authentication-Results at all.
        found.append(
            make_indicator(
                rule_id="auth-results-absent",
                category=IndicatorCategory.authentication,
                locus="header:Authentication-Results",
                fact=(
                    "The message carries no Authentication-Results header, so no "
                    "receiving server recorded an SPF, DKIM or DMARC verdict for it."
                ),
                weight=0.30,
                severity_floor=Severity.low,
                rationale=(
                    "Without it there is no independent statement about the sender at "
                    "all - every remaining signal is the sender's own text. Weak on "
                    "its own, because exported and forwarded mail often lacks it."
                ),
            )
        )

    found.extend(_domain_mismatches(message))
    return found


def _domain_mismatches(message: NormalizedMessage) -> list[Indicator]:
    """Where the reply and envelope paths disagree with the visible sender."""
    found: list[Indicator] = []
    sender_domain = registrable_domain(message.sender.domain)
    if not sender_domain:
        return found

    if message.reply_to is not None:
        reply_domain = registrable_domain(message.reply_to.domain)
        if reply_domain and reply_domain != sender_domain:
            found.append(
                make_indicator(
                    rule_id="auth-reply-to-mismatch",
                    category=IndicatorCategory.authentication,
                    locus="header:Reply-To",
                    fact=(
                        f"Replies go to {reply_domain!r}, not to the sender's domain "
                        f"{sender_domain!r}."
                    ),
                    weight=0.70,
                    severity_floor=Severity.medium,
                    rationale=(
                        "Redirecting replies is how a spoofed sender receives the "
                        "recipient's answer. Legitimate senders do use separate reply "
                        "domains, so this is strong but not conclusive alone."
                    ),
                    evidence={
                        "reply_to": message.reply_to.address,
                        "sender": message.sender.address,
                    },
                    discriminator=reply_domain,
                )
            )

    if message.return_path is not None:
        envelope_domain = registrable_domain(message.return_path.domain)
        if envelope_domain and envelope_domain != sender_domain:
            found.append(
                make_indicator(
                    rule_id="auth-envelope-mismatch",
                    category=IndicatorCategory.authentication,
                    locus="header:Return-Path",
                    fact=(
                        f"The envelope sender is {envelope_domain!r} while the From "
                        f"header claims {sender_domain!r}."
                    ),
                    weight=0.60,
                    severity_floor=Severity.medium,
                    rationale=(
                        "The envelope sender is what the sending server actually "
                        "declared, so a mismatch shows the visible From was chosen "
                        "independently of it. Bulk senders and mailing lists do this "
                        "legitimately, which caps how much it can weigh."
                    ),
                    evidence={
                        "return_path": message.return_path.address,
                        "sender": message.sender.address,
                    },
                    discriminator=envelope_domain,
                )
            )

    return found
