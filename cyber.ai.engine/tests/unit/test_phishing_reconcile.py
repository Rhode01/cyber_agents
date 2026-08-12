"""Reconciliation tests: the boundary where the model stops being trusted.

The rule is asymmetric, and the asymmetry is the point:

* an id the model **omitted** costs nothing - ranking decides order, never membership;
* an id the model **invented** is dropped, because it is the model asserting evidence no
  rule found, and accepting one would let a crafted message manufacture a finding.

That is also the reason indicator ids are opaque and content-addressed rather than
positional: a shifted positional index is indistinguishable from a real one, while an
unknown opaque id is detectable.
"""

from __future__ import annotations

from cyber_contracts import Severity

from app.agents.phishing.indicators import Indicator, IndicatorCategory, make_indicator
from app.agents.phishing.reconcile import reconcile


def indicator(rule_id: str, weight: float = 0.5) -> Indicator:
    return make_indicator(
        rule_id=rule_id,
        category=IndicatorCategory.url,
        locus=f"locus:{rule_id}",
        fact=f"fact for {rule_id}",
        weight=weight,
        severity_floor=Severity.medium,
        rationale="because",
    )


ONE = indicator("one", 0.9)
TWO = indicator("two", 0.7)
THREE = indicator("three", 0.5)
ALL = [ONE, TWO, THREE]


def test_a_full_ranking_is_honoured() -> None:
    result = reconcile(ALL, [THREE.indicator_id, ONE.indicator_id, TWO.indicator_id])

    assert [item.rule_id for item in result.ranked] == ["three", "one", "two"]
    assert result.had_anomalies is False


def test_a_partial_ranking_leads_and_the_rest_follow_in_rule_order() -> None:
    """Ranking decides order, never membership."""
    result = reconcile(ALL, [THREE.indicator_id])

    assert [item.rule_id for item in result.ranked] == ["three", "one", "two"]
    assert result.named_ids == (THREE.indicator_id,)


def test_an_empty_ranking_keeps_every_indicator_in_rule_order() -> None:
    """A model that ranks nothing has not deleted the evidence."""
    result = reconcile(ALL, [])

    assert [item.rule_id for item in result.ranked] == ["one", "two", "three"]
    assert result.named_ids == ()


def test_an_invented_id_is_dropped_and_recorded() -> None:
    """The case that matters: the model naming evidence no rule established."""
    result = reconcile(ALL, ["ind_deadbeef", ONE.indicator_id])

    assert result.unknown_ids == ("ind_deadbeef",)
    assert result.named_ids == (ONE.indicator_id,)
    # It reaches no finding, because membership comes from the rule engine.
    assert all(item.indicator_id != "ind_deadbeef" for item in result.ranked)
    assert len(result.ranked) == 3
    assert result.had_anomalies is True


def test_only_invented_ids_still_yields_every_real_indicator() -> None:
    """A completely fabricated ranking degrades to rule order, not to nothing."""
    result = reconcile(ALL, ["ind_aaa", "ind_bbb"])

    assert [item.rule_id for item in result.ranked] == ["one", "two", "three"]
    assert len(result.unknown_ids) == 2


def test_a_duplicate_id_collapses_and_first_occurrence_wins() -> None:
    result = reconcile(ALL, [TWO.indicator_id, TWO.indicator_id, ONE.indicator_id])

    assert result.named_ids == (TWO.indicator_id, ONE.indicator_id)
    assert result.duplicate_ids == (TWO.indicator_id,)
    assert len(result.ranked) == 3


def test_whitespace_around_an_id_is_tolerated() -> None:
    """Models pad list items. Failing on a stray space would drop real evidence."""
    result = reconcile(ALL, [f"  {ONE.indicator_id}  "])

    assert result.named_ids == (ONE.indicator_id,)
    assert result.unknown_ids == ()


def test_every_indicator_appears_exactly_once() -> None:
    """The invariant the finding depends on: no duplication, no loss."""
    result = reconcile(ALL, [ONE.indicator_id, ONE.indicator_id, "ind_fake", TWO.indicator_id])

    ids = [item.indicator_id for item in result.ranked]
    assert len(ids) == len(set(ids)) == 3
    assert set(ids) == {item.indicator_id for item in ALL}


def test_reconciling_an_empty_indicator_set_is_safe() -> None:
    """`reason` skips the model when nothing fired, but the function must not crash."""
    result = reconcile([], ["ind_anything"])

    assert result.ranked == ()
    assert result.unknown_ids == ("ind_anything",)


def test_reconciliation_is_pure() -> None:
    """No mutation of the input, so a caller can reuse the list."""
    original = list(ALL)

    reconcile(ALL, [THREE.indicator_id])

    assert ALL == original
