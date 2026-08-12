"""What the model is allowed to say about a message.

The model receives indicators the rule engine already established and writes the
analyst-facing prose for them. It cannot add one, cannot invent a header or a domain,
and cannot lower the severity below the deterministic floor - that last one is enforced
in ``nodes.emit_findings`` regardless of what it returns here.

**Deliberately constraint-free.** No ``min_length``, no ``ge``/``le``, no ``pattern``,
no defaults. OpenAI's strict Structured Outputs mode forwards a Pydantic schema's
constraints to the endpoint unvalidated, where an unsupported keyword fails the call
outright, and it rewrites ``required`` to every property so a default could never fire.
An optional field is therefore typed ``X | None``. Bounds are applied on our side,
after the model answers; ``tests/unit/test_assessment_schema.py`` fails the build if a
constraint or default appears here.

**Field order is generation order**, and that is a design decision rather than tidiness.
The model fills these top to bottom, so each field it writes conditions the next:

1. ``injection`` first - a model that has just written down "this content told me to
   ignore my instructions" reads everything after it more carefully.
2. ``key_indicator_ids`` next - commit to which evidence matters before interpreting it.
3. ``explanation`` before ``verdict`` - reason, then conclude. A verdict written first
   turns the explanation into justification for a decision already made.
4. ``severity`` and ``confidence`` last, once the reasoning exists to support them.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict

from app.agents.common.assessment_schema import ConfidenceBand, InjectionReport


class PhishingVerdict(StrEnum):
    """The headline answer.

    Three values, not a probability. An analyst triages by "do I act on this", and a
    continuous score would only be re-bucketed into these three anyway - with the
    bucketing hidden somewhere less visible than here.
    """

    clean = "clean"
    suspicious = "suspicious"
    phishing = "phishing"


class PhishingAssessment(BaseModel):
    """The model's write-up of one message."""

    model_config = ConfigDict(extra="forbid")

    injection: InjectionReport
    """Filled FIRST. Whether the content appeared to be addressing the analyser rather
    than the recipient. Independent of the deterministic injection rule - either one
    firing raises a finding."""

    key_indicator_ids: list[str]
    """The supplied indicator ids that drove the verdict, most important first.

    Ids not on the authoritative list are dropped by ``reconcile``, because an id the
    model invented is it asserting evidence no rule found. Omitting some is fine: this
    is a ranking hint, not an obligation to cover everything."""

    explanation: str
    """Two to four plain sentences an analyst can act on, written BEFORE the verdict.

    Must describe what was found and why it matters, in the language of the evidence -
    not restate the indicator list."""

    verdict: PhishingVerdict

    severity: str
    """critical | high | medium | low | info.

    A free string rather than an enum, following the vulnerability agent: models write
    "Medium" and "informational" as readily as "medium", and mapping afterwards through
    ``agents.common.findings.resolve_severity`` - which falls back to the rule floor
    when it cannot tell - is more robust than a schema the model has to match exactly.

    May be raised above the deterministic floor. Any attempt to go below it is
    overridden in code."""

    confidence: ConfidenceBand
    """How sure the model is about its *explanation*, not about whether the indicators
    are real - those are already established."""

    title: str
    """One short analyst-facing line. Becomes ``Finding.title``."""

    recommendation: str
    """What to do about it: block, delete, warn the recipient, reset credentials."""
