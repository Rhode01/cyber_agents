"""Strict-safe pieces shared by every agent's LLM-facing schema.

**Everything here must stay constraint-free.** OpenAI's strict Structured Outputs
mode forwards a Pydantic schema's constraints to the endpoint unvalidated, where an
unsupported keyword fails the call outright, and it rewrites ``required`` to include
every property so a default can never fire. So: no ``ge``/``le``, no ``min_length``,
no ``pattern``, no defaults. An optional field is typed ``X | None``.

Bounds belong on our side of the boundary, after the model answers.
``tests/unit/test_assessment_schema.py`` walks these models and fails the build if a
constraint or a default appears, which turns the paragraph above into something
enforced rather than something remembered.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Final

from pydantic import BaseModel, ConfigDict


class ConfidenceBand(StrEnum):
    """How sure the model is, in three steps.

    A band rather than ``confidence: float``, and the reason is specific. With
    ``ge``/``le`` unavailable a float is unbounded on the wire, and a model that
    means 85% writes ``85`` about as readily as ``0.85``. Clamping turns that into
    ``1.0`` - silently wrong in the direction that *overstates* certainty, which is
    the worst direction for a security tool. Three values are the best-supported
    strict construct there is, and the mapping below is ours, so recalibrating is a
    one-line change with no prompt edit.
    """

    low = "low"
    medium = "medium"
    high = "high"


CONFIDENCE_VALUES: Final[dict[ConfidenceBand, float]] = {
    ConfidenceBand.low: 0.35,
    ConfidenceBand.medium: 0.65,
    ConfidenceBand.high: 0.90,
}
"""Band to the ``Finding.confidence`` float. Deliberately never 1.0: the model is
explaining a deterministic detection, not certifying it."""


class InjectionSignal(StrEnum):
    """Whether the model believes the content was aimed at it.

    ``suspected`` matters as much as ``confirmed``. This is a second, independent
    detector alongside the deterministic rule - the model can notice being addressed
    in ways a pattern misses, and the rule catches what a compliant model would
    rather not mention. Either firing is enough to raise a finding.
    """

    none = "none"
    suspected = "suspected"
    confirmed = "confirmed"


class InjectionReport(BaseModel):
    """The model's own account of whether the input tried to instruct it.

    Filled **first** in every assessment schema, before any verdict field. A model
    that has just written down "this content told me to ignore my instructions" is in
    a better position to judge the rest of it than one asked about injection as an
    afterthought.
    """

    model_config = ConfigDict(extra="forbid")

    signal: InjectionSignal
    note: str
    """What in the content prompted this, in one sentence. Stored as evidence."""
