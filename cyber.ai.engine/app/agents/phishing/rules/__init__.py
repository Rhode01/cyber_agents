"""The deterministic rule engine.

``detect`` is the whole public surface: a ``NormalizedMessage`` in, an ordered list of
``Indicator`` out, no model involved and no network touched. Everything the phishing
agent reports traces back to this function, which is what makes the safety argument
work — the model downstream can rank and explain indicators but cannot create one.

Families are run in a fixed order and the result is sorted deterministically, so the
same message always yields the same list. Tests depend on that, and so does the
content-addressed indicator id.
"""

from __future__ import annotations

from collections.abc import Callable

from cyber_contracts import NormalizedMessage

from app.agents.phishing.indicators import Indicator, sort_key
from app.agents.phishing.rules import (
    attachments,
    authentication,
    content,
    identity,
    injection,
    urls,
)

# Ordered so the strongest families run first. The sort afterwards makes the order
# irrelevant to the output, but it keeps a partial result useful when debugging.
FAMILIES: tuple[Callable[[NormalizedMessage], list[Indicator]], ...] = (
    authentication.detect,
    identity.detect,
    urls.detect,
    attachments.detect,
    content.detect,
    injection.detect,
)


def detect(message: NormalizedMessage) -> list[Indicator]:
    """Run every rule family over one message.

    Returns:
        Indicators, heaviest first, then stable by rule id and locus. Duplicate ids are
        collapsed — two families can legitimately reach the same conclusion about the
        same locus, and the finding should say it once.
    """
    collected: dict[str, Indicator] = {}
    for family in FAMILIES:
        for indicator in family(message):
            # First wins. Families are ordered by strength, so the earlier one's framing
            # is the one worth keeping.
            collected.setdefault(indicator.indicator_id, indicator)

    return sorted(collected.values(), key=sort_key)


__all__ = ["FAMILIES", "detect", "injection"]
