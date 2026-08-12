"""Turning indicators into a severity floor, and the seam where ML will go.

Two jobs. First, decide how bad a set of indicators is, deterministically, so the
model has a floor it cannot argue below. Second, emit a named feature vector, so every
analysed message becomes one row of training data and a classifier can replace the
scorer later without touching the graph.

**Per-category saturation is the whole design.** A naive sum lets quantity stand in for
quality: a body stuffed with urgency phrases would outscore a DMARC failure, and
padding a message is free while forging a DKIM signature is not. So each category
contributes at most ``_CEILING`` no matter how many indicators it produced, and the
categories are weighted by how hard they are to fake.

The ML seam is deliberately narrow. ``Scorer`` takes indicators and returns a
``Score``; it does not see the message, so a future model is trained on the same
features that are stored on findings today, rather than on the raw text. That keeps
the "rules decide existence" invariant intact - a classifier can move the severity
band, never invent an indicator.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Final, Protocol

from cyber_contracts import SEVERITY_ORDER, Severity

from app.agents.phishing.indicators import Indicator, IndicatorCategory

SCORER_CONFIG_KEY: Final = "phishing_scorer"
"""``config["configurable"]`` key a test uses to inject a deterministic scorer."""

# How much each category can contribute at most, and how much its evidence is worth.
# Ordered by how hard the signal is to fake:
#
#   authentication  a receiving server's verdict against a published record
#   identity        a domain the attacker had to register
#   attachment      a file that will actually execute
#   injection       content aimed at this pipeline, which is unambiguous
#   url             where a link goes, which the sender chose but cannot hide
#   content         wording, which is free
_CEILING: Final[dict[IndicatorCategory, float]] = {
    IndicatorCategory.authentication: 1.00,
    IndicatorCategory.identity: 1.00,
    IndicatorCategory.attachment: 0.95,
    IndicatorCategory.injection: 0.90,
    IndicatorCategory.url: 0.90,
    IndicatorCategory.content: 0.45,
}

# Diminishing returns within a category: the first indicator counts fully, the second
# at a third, the rest barely. Three authentication failures are one broken sender, not
# three problems.
_DECAY: Final[tuple[float, ...]] = (1.0, 0.35, 0.15)

# Score at or above which each band applies, checked highest first.
_BANDS: Final[tuple[tuple[float, Severity], ...]] = (
    (0.80, Severity.critical),
    (0.55, Severity.high),
    (0.30, Severity.medium),
    (0.12, Severity.low),
)


@dataclass(frozen=True, slots=True)
class Score:
    """The deterministic verdict, before any model sees anything."""

    value: float
    """0.0-1.0. Not a probability - a calibrated ordering."""

    band: Severity
    """The severity floor. The model may raise the final severity above this and may
    never lower it below."""

    features: dict[str, float] = field(default_factory=dict)
    """Named feature vector, stored on every finding.

    This is a training-data schema, so the keys are stable: renaming one silently
    invalidates every row collected before the change. ``test_scoring`` pins them."""


class Scorer(Protocol):
    """How a set of indicators becomes a score.

    Deliberately given only indicators. A scorer that could see the message would be
    able to reach conclusions no rule reached, which is exactly what the rules-decide
    invariant forbids.
    """

    def __call__(self, indicators: Sequence[Indicator]) -> Score: ...


def _category_contribution(indicators: Sequence[Indicator]) -> float:
    """One category's contribution, with decay, before its ceiling is applied."""
    ordered = sorted((indicator.weight for indicator in indicators), reverse=True)
    total = 0.0
    for position, weight in enumerate(ordered):
        decay = _DECAY[position] if position < len(_DECAY) else _DECAY[-1] / (position + 1)
        total += weight * decay
    return total


def band_for(value: float) -> Severity:
    """The severity floor a score justifies."""
    for threshold, severity in _BANDS:
        if value >= threshold:
            return severity
    return Severity.info


def weighted_score(indicators: Sequence[Indicator]) -> Score:
    """The default scorer: per-category saturating sum.

    The combination term is the only place quantity helps, and it is capped. Evidence
    from several independent families is genuinely stronger than more of the same -
    a spoofed sender *and* a disguised executable *and* a deceptive link is a different
    thing from three urgency phrases.
    """
    by_category: dict[IndicatorCategory, list[Indicator]] = {}
    for indicator in indicators:
        by_category.setdefault(indicator.category, []).append(indicator)

    features: dict[str, float] = {}
    subtotal = 0.0

    for category in IndicatorCategory:
        found = by_category.get(category, [])
        ceiling = _CEILING[category]
        contribution = min(_category_contribution(found), ceiling) if found else 0.0
        subtotal += contribution
        features[f"cat_{category.value}_score"] = round(contribution, 4)
        features[f"cat_{category.value}_count"] = float(len(found))
        features[f"cat_{category.value}_max_weight"] = round(
            max((indicator.weight for indicator in found), default=0.0), 4
        )

    families = sum(1 for found in by_category.values() if found)
    # Corroboration across families, capped so it cannot dominate.
    combination = min(0.06 * max(0, families - 1), 0.18)

    # The ceilings sum well above 1.0, so normalise against the total available rather
    # than clamping - clamping would flatten everything strong into an identical 1.0
    # and lose the ordering the analyst actually reads.
    available = sum(_CEILING.values())
    value = min(subtotal / available + combination, 1.0)

    features["families_present"] = float(families)
    features["indicator_count"] = float(len(indicators))
    features["max_weight"] = round(
        max((indicator.weight for indicator in indicators), default=0.0), 4
    )
    features["combination_bonus"] = round(combination, 4)
    features["score"] = round(value, 4)

    return Score(value=round(value, 4), band=band_for(value), features=features)


def floor_from_indicators(indicators: Sequence[Indicator]) -> Severity:
    """The highest severity floor any single indicator claims.

    Used alongside the aggregate band: one disguised executable is critical on its own,
    and a score averaged across categories should not be able to talk that down. The
    final floor is the higher of the two.
    """
    if not indicators:
        return Severity.info
    return max(
        (indicator.severity_floor for indicator in indicators),
        key=lambda severity: SEVERITY_ORDER[severity],
    )


def score(indicators: Sequence[Indicator]) -> Score:
    """Score ``indicators``, taking the stronger of the aggregate and per-indicator floors."""
    aggregate = weighted_score(indicators)
    strongest = floor_from_indicators(indicators)

    if SEVERITY_ORDER[strongest] > SEVERITY_ORDER[aggregate.band]:
        return Score(value=aggregate.value, band=strongest, features=aggregate.features)
    return aggregate
