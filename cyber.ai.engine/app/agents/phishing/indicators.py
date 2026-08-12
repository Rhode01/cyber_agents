"""The deterministic unit of phishing detection.

An ``Indicator`` is a fact a rule established with no model involvement: this
header failed, this link points somewhere its text does not, this attachment has
two extensions. The model turns indicators into analyst-facing prose and ranks
them, but it can never create one - which is what stops a crafted email from
talking a finding into existence.

``indicator_id`` is content-addressed rather than sequential or natural, for the
same reasons written up in ``agents/vulnerability/candidates.py``:

* **Not sequential** (``ind_01``, ``ind_02``): a model that drops one entry shifts
  every later one, and a shifted id is indistinguishable from a real one. Opaque ids
  turn silent misattribution into a detectable "unknown id".
* **Not a natural key** (``sender:rule``): the sender address, the link host and the
  attachment filename are all attacker-chosen, so a natural key is one an attacker
  can collide on deliberately - and a collision would merge two findings, hiding one.

Content-addressing also means the same message yields the same ids on every run,
which is free determinism for tests.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from cyber_contracts import Severity


class IndicatorCategory(StrEnum):
    """Which family of rules produced an indicator.

    Categories are not cosmetic: ``scoring.WeightedScorer`` saturates per category, so
    ten content hits cannot outweigh one authentication failure. Adding a category
    changes the scoring shape, which is why the set is small and deliberate.
    """

    authentication = "authentication"
    """SPF, DKIM, DMARC, envelope and reply-path mismatches."""

    identity = "identity"
    """Who the message claims to be from: brand impersonation, lookalike domains."""

    url = "url"
    """Where the links actually go."""

    content = "content"
    """How the message is written: urgency, pressure, credential requests."""

    attachment = "attachment"
    """What is attached, judged from metadata only."""

    injection = "injection"
    """Content aimed at the model rather than the recipient."""


@dataclass(frozen=True, slots=True)
class Indicator:
    """One deterministic finding-in-waiting.

    Fields carrying attacker-authored text are marked UNTRUSTED. They are held
    verbatim and only ever reach a prompt inside the untrusted fence.
    """

    indicator_id: str
    rule_id: str
    category: IndicatorCategory

    locus: str
    """Where in the message this was found - ``header:From``, ``link:2``,
    ``attachment:invoice.pdf.exe``. Partly UNTRUSTED, since filenames appear here."""

    fact: str
    """A deterministic sentence rendered from a template. Embeds UNTRUSTED values, so
    it is data, never an instruction."""

    weight: float
    """Contribution to the deterministic score. See ``scoring``."""

    severity_floor: Severity
    """The floor this indicator alone justifies. The model may raise the final
    severity above the aggregate floor but never below it."""

    rationale: str
    """Why this rule exists at all. Trusted text, written by us, safe to show."""

    evidence: dict[str, Any] = field(default_factory=dict)
    """UNTRUSTED excerpts supporting the fact. Stored and displayed as text."""

    def for_prompt(self) -> dict[str, Any]:
        """The subset the model sees.

        ``weight`` and ``severity_floor`` are deliberately withheld. The model's job
        is to explain and rank, and handing it our numeric floor invites it to
        restate that number back as its own judgement - which would make the two
        signals correlated and the disagreement check meaningless.
        """
        return {
            "indicator_id": self.indicator_id,
            "category": self.category.value,
            "locus": self.locus,
            "fact": self.fact,
            "why_this_rule_exists": self.rationale,
        }

    def for_evidence(self) -> dict[str, Any]:
        """The full record stored on the resulting finding."""
        return {
            "indicator_id": self.indicator_id,
            "rule_id": self.rule_id,
            "category": self.category.value,
            "locus": self.locus,
            "fact": self.fact,
            "weight": self.weight,
            "severity_floor": self.severity_floor.value,
            "rationale": self.rationale,
            "evidence": self.evidence,
        }


def derive_indicator_id(rule_id: str, locus: str, discriminator: str = "") -> str:
    """Build a stable, opaque id for one detected fact.

    ``blake2s`` at 3 bytes gives 16.7M values, which is far more than the ~30
    indicators one message can produce, and short enough that a model copies it
    without transcription errors. It is not a security boundary - reconciliation
    checks membership against the authoritative list, so a guessed id is rejected
    the same way a hallucinated one is.
    """
    key = f"{rule_id}|{locus}|{discriminator}"
    digest = hashlib.blake2s(key.encode("utf-8"), digest_size=3).hexdigest()
    return f"ind_{digest}"


def make_indicator(
    *,
    rule_id: str,
    category: IndicatorCategory,
    locus: str,
    fact: str,
    weight: float,
    severity_floor: Severity,
    rationale: str,
    evidence: dict[str, Any] | None = None,
    discriminator: str = "",
) -> Indicator:
    """Construct an indicator with its id derived, so no rule invents one."""
    return Indicator(
        indicator_id=derive_indicator_id(rule_id, locus, discriminator),
        rule_id=rule_id,
        category=category,
        locus=locus,
        fact=fact,
        weight=weight,
        severity_floor=severity_floor,
        rationale=rationale,
        evidence=evidence or {},
    )


def sort_key(indicator: Indicator) -> tuple[float, str, str]:
    """Deterministic ordering: heaviest first, then stable by rule and locus.

    Used wherever a list of indicators is built, so prompts, findings and test
    expectations all agree without anyone sorting twice.
    """
    return (-indicator.weight, indicator.rule_id, indicator.locus)
