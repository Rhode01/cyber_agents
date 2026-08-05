"""Placeholder finding builder used by every Phase 1 agent.

This is the one piece of the scaffold that exists purely to be deleted: each
agent's ``emit_findings`` node calls it today and will build real findings from
real analysis in a later phase.
"""

from __future__ import annotations

from datetime import UTC, datetime

from cyberagents_contracts import AgentKind, FindingCreate, FindingType, Severity

from ai_engine.agents.common.untrusted import preview


def placeholder_finding(
    *,
    agent: AgentKind,
    source: str,
    asset: str | None,
    raw_input: str,
    summary: str,
) -> FindingCreate:
    """Build a contract-shaped finding that carries no detection claim."""
    return FindingCreate(
        agent=agent,
        # A placeholder asserts nothing about the artifact, so it is informational
        # by construction - not a weak claim about a real problem.
        finding_type=FindingType.informational,
        title=f"Phase 1 placeholder: {agent.value} agent reached",
        description=(
            f"{summary} The {agent.value} agent graph ran end to end and returned this "
            "placeholder. No detection logic, no rules, and no model call are wired up yet."
        ),
        severity=Severity.info,
        confidence=0.0,
        source=source,
        asset=asset,
        evidence={
            "raw_input_preview": preview(raw_input),
            "raw_input_length": len(raw_input),
            "note": "Untrusted data. Stored and displayed, never followed as instructions.",
        },
        recommendation=None,
        raw_reference=None,
        detected_at=datetime.now(UTC),
    )
