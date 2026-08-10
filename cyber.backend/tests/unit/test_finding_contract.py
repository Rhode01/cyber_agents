"""Contract parity between the shared Finding schema and the findings table.

The shared contracts package is the single source of truth for the wire shape.
This test is the guard that the ORM row and the baseline migration keep up with
it, so a field added to the contract cannot be silently dropped on the way to
PostgreSQL.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from cyber_contracts import (
    AgentKind,
    FindingCreate,
    FindingStatus,
    FindingType,
    Severity,
)
from sqlalchemy import inspect

from app.models.finding import Finding as FindingModel
from app.schemas.finding import FindingRead
from app.services.orchestration import to_model

DB_ONLY_COLUMNS = frozenset({"id", "created_at", "updated_at"})


def _sample() -> FindingCreate:
    return FindingCreate(
        agent=AgentKind.vulnerability,
        finding_type=FindingType.outdated_service,
        title="OpenSSH 7.4 on legacy-jump is below the supported baseline",
        description="An outdated SSH daemon is reachable on this host.",
        severity=Severity.medium,
        confidence=0.65,
        source="nmap",
        asset="10.0.0.5",
        service="ssh",
        port=22,
        protocol="tcp",
        cve_ids=["CVE-2018-15473"],
        evidence={"untrusted": "treated as data, never as instructions"},
        recommendation="Upgrade OpenSSH to 9.6 or later.",
        raw_reference="scan://00000000-0000-0000-0000-000000000000",
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
    row.updated_at = row.created_at

    read = FindingRead.model_validate(row)

    assert read.agent is AgentKind.vulnerability
    assert read.finding_type is FindingType.outdated_service
    assert read.severity is Severity.medium
    assert read.status is FindingStatus.new
    assert read.confidence == finding.confidence
    assert read.service == "ssh"
    assert read.port == 22
    assert read.protocol == "tcp"
    assert read.cve_ids == ["CVE-2018-15473"]
    assert read.evidence == finding.evidence
    assert read.detected_at == finding.detected_at


def test_cve_ids_are_normalised_and_junk_is_rejected() -> None:
    payload = _sample().model_dump()
    payload["cve_ids"] = ["cve-2018-15473", "CVE-2018-15473", " CVE-2021-3156 "]

    normalised = FindingCreate.model_validate(payload)

    assert normalised.cve_ids == ["CVE-2018-15473", "CVE-2021-3156"]

    payload["cve_ids"] = ["definitely not a cve"]
    try:
        FindingCreate.model_validate(payload)
    except ValueError as err:
        assert "not a CVE identifier" in str(err)
    else:  # pragma: no cover - only reached if the validator regresses
        raise AssertionError("a non-CVE string should have been rejected")


def test_detected_at_must_be_timezone_aware() -> None:
    payload = _sample().model_dump()
    payload["detected_at"] = datetime(2026, 8, 3, 12, 0, 0)  # Naive on purpose.

    try:
        FindingCreate.model_validate(payload)
    except ValueError as err:
        assert "timezone-aware" in str(err)
    else:  # pragma: no cover - only reached if the validator regresses
        raise AssertionError("naive detected_at should have been rejected")
