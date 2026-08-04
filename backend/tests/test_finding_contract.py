"""Contract parity between the shared Finding schema and the findings table.

The shared contracts package is the single source of truth for the wire shape.
This test is the guard that the ORM row and the baseline migration keep up with
it, so a field added to the contract cannot be silently dropped on the way to
PostgreSQL.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from cyberagents_contracts import AgentKind, FindingCreate, Severity
from sqlalchemy import inspect

from app.models.finding import Finding as FindingModel
from app.schemas.finding import FindingRead
from app.services.orchestration import to_model

DB_ONLY_COLUMNS = frozenset({"id", "created_at"})


def _sample() -> FindingCreate:
    return FindingCreate(
        agent=AgentKind.vulnerability,
        title="Placeholder finding",
        description="Produced by the Phase 1 scaffold, not by real detection logic.",
        severity=Severity.medium,
        confidence=0.5,
        source="nmap",
        asset="host.example.internal",
        evidence={"untrusted": "treated as data, never as instructions"},
        recommendation="Nothing to do - this is scaffolding.",
        raw_reference="artifact://placeholder",
        detected_at=datetime.now(UTC),
    )


def test_orm_columns_match_the_contract() -> None:
    contract_fields = set(FindingCreate.model_fields)
    table_columns = {column.key for column in inspect(FindingModel).columns}

    assert table_columns - DB_ONLY_COLUMNS == contract_fields


def test_contract_round_trips_through_the_orm_mapping() -> None:
    finding = _sample()

    row = to_model(finding)
    row.id = uuid.uuid4()
    row.created_at = datetime.now(UTC)

    read = FindingRead.model_validate(row)

    assert read.agent is AgentKind.vulnerability
    assert read.severity is Severity.medium
    assert read.confidence == finding.confidence
    assert read.evidence == finding.evidence
    assert read.detected_at == finding.detected_at


def test_detected_at_must_be_timezone_aware() -> None:
    payload = _sample().model_dump()
    payload["detected_at"] = datetime(2026, 8, 3, 12, 0, 0)  # Naive on purpose.

    try:
        FindingCreate.model_validate(payload)
    except ValueError as err:
        assert "timezone-aware" in str(err)
    else:  # pragma: no cover - only reached if the validator regresses
        raise AssertionError("naive detected_at should have been rejected")
