"""Rules about how a message is written.

The weakest family in the engine, and it is scored that way. Urgency is not evidence
of fraud - real security alerts are urgent, real invoices are overdue, and real
colleagues do ask for things quickly. What distinguishes a lure is the *combination*:
pressure plus a credential request plus a single link somewhere unrelated.

Two design choices follow from that:

* **Position matters.** A phrase in the subject is a claim the message is built
  around; the same phrase in a footer is boilerplate. Subject hits count for more.
* **One indicator per kind, not per phrase.** Ten urgency phrases are one fact about
  the message's tone, not ten facts. Emitting them separately would let quantity
  substitute for quality, which is exactly the failure the previous implementation
  had - and combined with its skip-the-model shortcut, it is why ordinary mail got
  labelled phishing with nothing explaining why.
"""

from __future__ import annotations

from collections import defaultdict

from cyber_contracts import NormalizedMessage, Severity

from app.agents.phishing import knowledge
from app.agents.phishing.indicators import (
    Indicator,
    IndicatorCategory,
    make_indicator,
)

SUBJECT_MULTIPLIER = 1.25
"""A phrase in the subject weighs more than the same phrase in the body."""

MAX_CONTENT_WEIGHT = 0.75
"""Ceiling on any content indicator, applied after the subject multiplier.

Without it, a heavy phrase in the subject reached 0.94 - above a DMARC failure (0.90)
and a disguised executable (0.90). Since the prompt orders indicators by weight, the
model would then be shown *wording* as the most important fact about the message,
which inverts the design: how something is written is the weakest evidence here, and
no amount of phrasing should outrank a cryptographic failure or a file that will
execute. The cap enforces that ordering rather than trusting the numbers to happen to
land in the right places."""

MAX_PHRASES_REPORTED = 6
"""How many matched phrases go into the evidence, heaviest first. The fact sentence
names a few; the rest are a count, so a keyword-stuffed body cannot flood the
prompt."""

_KIND_RATIONALE: dict[str, str] = {
    "urgency": (
        "Time pressure is used to stop the recipient checking. It is common in "
        "legitimate mail too, so it counts as tone rather than proof."
    ),
    "threat": (
        "Threatening loss of access or legal consequences raises the cost of pausing "
        "to verify, which is the point of including it."
    ),
    "credential": (
        "Asking the recipient to confirm, verify or re-enter credentials is the actual "
        "objective of most phishing. Legitimate senders send you to a site you already "
        "know rather than asking for details in a message."
    ),
    "payment": (
        "Invoice and payment pressure is the shape of business email compromise, where "
        "the goal is a transfer rather than a password."
    ),
    "secrecy": (
        "Asking the recipient not to discuss the request isolates them from the "
        "colleague who would notice. Legitimate internal requests survive being "
        "mentioned."
    ),
}

_KIND_FLOOR: dict[str, Severity] = {
    "urgency": Severity.low,
    "threat": Severity.low,
    "credential": Severity.medium,
    "payment": Severity.medium,
    "secrecy": Severity.medium,
}


def detect(message: NormalizedMessage) -> list[Indicator]:
    """Every content indicator this message earns."""
    subject = message.subject.lower()
    body = message.body_text.lower()
    if not subject.strip() and not body.strip():
        return []

    # kind -> [(effective weight, phrase text, where)]
    matches: dict[str, list[tuple[float, str, str]]] = defaultdict(list)
    for phrase in knowledge.phrases():
        in_subject = phrase.text in subject
        in_body = phrase.text in body
        if not (in_subject or in_body):
            continue
        weight = phrase.weight * SUBJECT_MULTIPLIER if in_subject else phrase.weight
        where = "subject" if in_subject else "body"
        matches[phrase.kind].append((min(weight, MAX_CONTENT_WEIGHT), phrase.text, where))

    found: list[Indicator] = [
        _indicator_for(kind, sorted(hits, reverse=True)) for kind, hits in sorted(matches.items())
    ]

    found.extend(_single_link_plus_pressure(message, matches))
    return found


def _indicator_for(kind: str, hits: list[tuple[float, str, str]]) -> Indicator:
    """One indicator summarising every phrase of one kind."""
    heaviest_weight, heaviest_phrase, where = hits[0]
    named = [phrase for _, phrase, _ in hits[:3]]
    quoted = ", ".join(repr(phrase) for phrase in named)
    remainder = len(hits) - len(named)
    tail = f", and {remainder} more" if remainder > 0 else ""

    return make_indicator(
        rule_id=f"content-{kind}-language",
        category=IndicatorCategory.content,
        locus=f"{where}:phrases",
        fact=(
            f"The message uses {kind} language: {quoted}{tail}. The strongest is "
            f"{heaviest_phrase!r}, found in the {where}."
        ),
        # The heaviest single phrase, not the sum: five weak phrases must not add up to
        # a strong one, because a body can contain any number of them for free.
        weight=heaviest_weight,
        severity_floor=_KIND_FLOOR.get(kind, Severity.low),
        rationale=_KIND_RATIONALE.get(kind, "Language associated with social engineering."),
        evidence={
            "kind": kind,
            "matched": [{"phrase": phrase, "where": place} for _, phrase, place in
                        hits[:MAX_PHRASES_REPORTED]],
            "match_count": len(hits),
        },
        discriminator=kind,
    )


def _single_link_plus_pressure(
    message: NormalizedMessage, matches: dict[str, list[tuple[float, str, str]]]
) -> list[Indicator]:
    """The classic lure shape: pressure, and exactly one place to click.

    This is a *combination* rule, and it is the one that earns its weight. Urgency
    alone is ordinary; urgency with a single call to action and nothing else is the
    structure of a credential-harvesting message.
    """
    pressure_kinds = {"urgency", "threat", "credential"} & matches.keys()
    if not pressure_kinds or len(message.links) != 1:
        return []

    return [
        make_indicator(
            rule_id="content-single-link-with-pressure",
            category=IndicatorCategory.content,
            locus="message:shape",
            fact=(
                "The message combines pressure language with exactly one link, giving "
                "the recipient a single action to take under time pressure."
            ),
            weight=0.65,
            severity_floor=Severity.medium,
            rationale=(
                "Legitimate mail usually offers context, alternatives and more than one "
                "route. One link plus a deadline is the shape of a lure rather than a "
                "notification."
            ),
            evidence={
                "link": message.links[0].url,
                "pressure_kinds": sorted(pressure_kinds),
            },
        )
    ]


#
# There is deliberately no "HTML with no plain-text alternative" rule.
#
# It was written and then removed as unreachable: the parser always populates
# `body_text`, deriving it from the markup when there is no text/plain part, so a
# condition of "html present and body_text empty" can never hold. Distinguishing
# "text came from a plain part" from "text was derived" would need a new field on
# NormalizedMessage, which is not worth adding for a signal this weak - a great deal of
# legitimate marketing mail is HTML-only.
#
