"""Scoring tests.

The properties that matter are comparative, not absolute. Nobody can say whether 0.63
is the right score for a message; what has to hold is that quantity cannot substitute
for quality, that a single decisive indicator cannot be averaged away, and that the
feature keys stay stable because they are a training-data schema.
"""

from __future__ import annotations

from cyber_contracts import Severity

from app.agents.phishing.indicators import Indicator, IndicatorCategory, make_indicator
from app.agents.phishing.scoring import (
    band_for,
    floor_from_indicators,
    score,
    weighted_score,
)


def indicator(
    category: IndicatorCategory,
    weight: float,
    floor: Severity = Severity.medium,
    rule_id: str = "",
    locus: str = "",
) -> Indicator:
    return make_indicator(
        rule_id=rule_id or f"test-{category.value}-{weight}",
        category=category,
        locus=locus or f"locus:{weight}",
        fact="a fact",
        weight=weight,
        severity_floor=floor,
        rationale="because",
    )


def test_no_indicators_scores_zero_and_info() -> None:
    result = score([])

    assert result.value == 0.0
    assert result.band is Severity.info


def test_one_authentication_failure_outranks_many_content_hits() -> None:
    """The property the per-category ceiling exists to guarantee.

    Padding a body with urgency phrases is free; forging a DKIM signature is not, so no
    amount of wording may outscore one cryptographic failure.
    """
    content_flood = [
        indicator(IndicatorCategory.content, 0.75, rule_id=f"content-{n}", locus=f"l{n}")
        for n in range(10)
    ]
    one_auth = [indicator(IndicatorCategory.authentication, 0.90, Severity.high)]

    assert weighted_score(one_auth).value > weighted_score(content_flood).value


def test_repeating_one_category_has_diminishing_returns() -> None:
    """Three authentication failures are one broken sender, not three problems."""
    one = weighted_score([indicator(IndicatorCategory.authentication, 0.9, rule_id="a")])
    three = weighted_score(
        [
            indicator(IndicatorCategory.authentication, 0.9, rule_id="a"),
            indicator(IndicatorCategory.authentication, 0.9, rule_id="b"),
            indicator(IndicatorCategory.authentication, 0.9, rule_id="c"),
        ]
    )

    assert three.value > one.value
    # But nowhere near three times as much.
    assert three.value < one.value * 2


def test_evidence_from_several_families_beats_more_of_one() -> None:
    """Corroboration across independent families is genuinely stronger."""
    one_family = [
        indicator(IndicatorCategory.content, 0.75, rule_id=f"c{n}", locus=f"l{n}")
        for n in range(4)
    ]
    four_families = [
        indicator(IndicatorCategory.authentication, 0.75),
        indicator(IndicatorCategory.identity, 0.75),
        indicator(IndicatorCategory.url, 0.75),
        indicator(IndicatorCategory.attachment, 0.75),
    ]

    assert weighted_score(four_families).value > weighted_score(one_family).value


def test_the_combination_bonus_is_capped() -> None:
    """It corroborates; it must not dominate."""
    every_family = [indicator(category, 0.5) for category in IndicatorCategory]

    assert weighted_score(every_family).features["combination_bonus"] <= 0.18


def test_a_single_critical_indicator_is_not_averaged_away() -> None:
    """One disguised executable is critical whatever the aggregate says.

    The aggregate spreads across six categories, so a lone indicator scores low - and a
    file that will execute must not be reported as low severity because it arrived on
    its own.
    """
    lone_executable = [
        indicator(IndicatorCategory.attachment, 0.90, Severity.critical)
    ]

    result = score(lone_executable)

    assert result.band is Severity.critical
    assert result.value < 0.3  # the aggregate really is low
    assert floor_from_indicators(lone_executable) is Severity.critical


def test_the_band_is_the_stronger_of_aggregate_and_per_indicator_floor() -> None:
    many_weak = [
        indicator(IndicatorCategory.content, 0.4, Severity.low, rule_id=f"c{n}", locus=f"l{n}")
        for n in range(3)
    ]

    aggregate_only = weighted_score(many_weak)
    combined = score(many_weak)

    assert combined.band is not Severity.info
    assert combined.value == aggregate_only.value


def test_bands_are_ordered() -> None:
    assert band_for(0.95) is Severity.critical
    assert band_for(0.60) is Severity.high
    assert band_for(0.35) is Severity.medium
    assert band_for(0.15) is Severity.low
    assert band_for(0.01) is Severity.info


def test_scores_never_leave_the_unit_interval() -> None:
    everything = [
        indicator(category, 1.0, rule_id=f"{category.value}-{n}", locus=f"l{n}")
        for category in IndicatorCategory
        for n in range(5)
    ]

    result = weighted_score(everything)

    assert 0.0 <= result.value <= 1.0


def test_feature_keys_are_stable() -> None:
    """These keys are a training-data schema.

    Renaming one silently invalidates every row collected before the change, and the
    whole point of storing them is that a classifier can be trained later on data
    gathered now. So the set is pinned here rather than left to drift.
    """
    result = weighted_score([indicator(IndicatorCategory.url, 0.8)])

    expected = {"families_present", "indicator_count", "max_weight", "combination_bonus", "score"}
    for category in IndicatorCategory:
        expected |= {
            f"cat_{category.value}_score",
            f"cat_{category.value}_count",
            f"cat_{category.value}_max_weight",
        }

    assert set(result.features) == expected


def test_every_feature_is_a_float() -> None:
    """A classifier consumes this vector directly; a stray string would break training."""
    result = weighted_score([indicator(IndicatorCategory.identity, 0.9)])

    assert all(isinstance(value, float) for value in result.features.values())


def test_features_describe_what_fired() -> None:
    result = weighted_score(
        [
            indicator(IndicatorCategory.url, 0.9),
            indicator(IndicatorCategory.url, 0.5, rule_id="u2", locus="l2"),
            indicator(IndicatorCategory.content, 0.4),
        ]
    )

    assert result.features["cat_url_count"] == 2.0
    assert result.features["cat_url_max_weight"] == 0.9
    assert result.features["cat_attachment_count"] == 0.0
    assert result.features["families_present"] == 2.0
    assert result.features["indicator_count"] == 3.0


def test_scoring_is_deterministic() -> None:
    indicators = [
        indicator(IndicatorCategory.authentication, 0.9),
        indicator(IndicatorCategory.url, 0.6),
    ]

    assert score(indicators) == score(list(reversed(indicators)))
