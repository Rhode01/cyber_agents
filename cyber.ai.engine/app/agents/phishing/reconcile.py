"""Matching the model's answer back to the indicators that exist.

Pure, and small on purpose: this is the boundary where the model stops being trusted.

The rule is asymmetric. An id the model **omitted** costs nothing - ``key_indicator_ids``
is a ranking hint, so anything unranked simply keeps its rule-engine position. An id the
model **invented** is dropped and logged, because an unknown id is the model asserting
evidence no rule found, and accepting one would let a crafted message manufacture a
finding. That asymmetry is the whole reason the ids are opaque and content-addressed
rather than positional.

Contrast with the vulnerability agent, where every candidate needs its own write-up and a
missing one is a real gap worth a repair turn. Here there is nothing to repair.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from app.agents.phishing.indicators import Indicator
from app.core.logging import get_logger

logger = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class Reconciliation:
    """The outcome of matching a model's ranking against the real indicators."""

    ranked: tuple[Indicator, ...]
    """Every indicator, in the order the finding should present them: the model's
    ranking first, then the rest in rule order. Always the full set - ranking decides
    order, never membership."""

    named_ids: tuple[str, ...]
    """The ids the model ranked, after dropping unknowns and duplicates."""

    unknown_ids: tuple[str, ...]
    """Ids the model produced that do not exist. Dropped, and worth an alert if it keeps
    happening - it means the model is inventing evidence."""

    duplicate_ids: tuple[str, ...]
    """Ids the model listed more than once. First occurrence wins."""

    @property
    def had_anomalies(self) -> bool:
        return bool(self.unknown_ids or self.duplicate_ids)


def reconcile(
    indicators: Sequence[Indicator], key_indicator_ids: Sequence[str]
) -> Reconciliation:
    """Order ``indicators`` by the model's ranking, discarding anything invented.

    Args:
        indicators: The authoritative set, already in rule order.
        key_indicator_ids: What the model said mattered, most important first.

    Returns:
        A ``Reconciliation`` whose ``ranked`` contains every input indicator exactly
        once.
    """
    by_id = {indicator.indicator_id: indicator for indicator in indicators}

    named: list[str] = []
    unknown: list[str] = []
    duplicate: list[str] = []
    seen: set[str] = set()

    for candidate in key_indicator_ids:
        identifier = candidate.strip()
        if identifier not in by_id:
            unknown.append(candidate)
            continue
        if identifier in seen:
            duplicate.append(identifier)
            continue
        seen.add(identifier)
        named.append(identifier)

    # Ranked first, then everything the model did not mention, in rule order. Membership
    # comes from the rule engine; the model only reorders.
    ranked = [by_id[identifier] for identifier in named]
    ranked.extend(
        indicator for indicator in indicators if indicator.indicator_id not in seen
    )

    if unknown:
        logger.warning(
            "phishing.reconcile.unknown_ids",
            count=len(unknown),
            ids=unknown[:10],
            note="dropped: the model named evidence no rule established",
        )
    if duplicate:
        logger.info("phishing.reconcile.duplicate_ids", count=len(duplicate), ids=duplicate[:10])

    return Reconciliation(
        ranked=tuple(ranked),
        named_ids=tuple(named),
        unknown_ids=tuple(unknown),
        duplicate_ids=tuple(duplicate),
    )
