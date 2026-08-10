"""Shared helpers for turning raw agent output into contract findings."""

from __future__ import annotations

from typing import Any, Final

from cyber_contracts import FindingType, Severity

# Scanners and models both use "informational" as often as "info", and Trivy
# emits "UNKNOWN". Everything unrecognised falls to the caller's default rather
# than to a guess. Previously copy-pasted into all four agents' nodes.py.
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
    """Map a scanner's or model's severity string onto the contract enum."""
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
