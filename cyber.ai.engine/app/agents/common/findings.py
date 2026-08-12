"""Shared helpers for turning raw agent output into contract findings."""

from __future__ import annotations

from typing import Any, Final

from cyber_contracts import FindingType, Severity

# Scanners and models both use "informational" as often as "info", Trivy emits
# "UNKNOWN", OpenVAS emits "Log", and a phishing verdict can be "safe".
# Everything unrecognised falls to the caller's default rather than to a guess.
#
# The four agents each kept their own copy of this before, and they had already
# drifted: only webapp knew "informational", only phishing knew "safe". The union
# lives here, but the *default* stays per-caller - see resolve_severity.
_SEVERITY_ALIASES: Final[dict[str, Severity]] = {
    "critical": Severity.critical,
    "high": Severity.high,
    "medium": Severity.medium,
    "moderate": Severity.medium,
    "low": Severity.low,
    "info": Severity.info,
    "informational": Severity.info,
    "none": Severity.info,
    "log": Severity.info,
    "safe": Severity.info,
}


def parse_severity(value: object) -> Severity | None:
    """Map a severity string onto the contract enum, or None if unrecognised.

    Use this when "the scanner did not rate this" has to stay distinguishable
    from "the scanner rated it info".
    """
    if isinstance(value, Severity):
        return value
    if value is None:
        return None
    return _SEVERITY_ALIASES.get(str(value).strip().lower())


def resolve_severity(value: object, default: Severity = Severity.info) -> Severity:
    """Map a scanner's or model's severity string onto the contract enum.

    ``default`` is deliberately a parameter rather than a constant: an unrecognised
    phishing verdict is not the same risk as an unrecognised port scan result, so
    the phishing agent falls back to ``medium`` where the others fall back to
    ``info``. Folding that into one shared default would quietly downgrade every
    phishing verdict the model phrased unexpectedly.
    """
    parsed = parse_severity(value)
    return default if parsed is None else parsed


def resolve_finding_type(raw: dict[str, Any], default: FindingType) -> FindingType:
    """Validate a possibly-absent LLM-provided ``finding_type`` against the enum.

    The LLM may emit an arbitrary string for ``finding_type``; anything that is
    not one of the contract values falls back to the agent's default so the
    backend never receives an invalid type.
    """
    value = raw.get("finding_type")
    if not value:
        return default
    try:
        return FindingType(value)
    except ValueError:
        return default
