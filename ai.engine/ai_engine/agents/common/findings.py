"""Shared helpers for turning raw agent output into contract findings."""

from __future__ import annotations

from typing import Any

from cyberagents_contracts import FindingType


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
