"""The uploaded-scan pipeline: upload -> parse -> assess -> persist.

This is the flow that was broken end to end. The client posted a
`VulnerabilityAnalyzeRequest` to `/agents/vulnerability/analyze`, which forbids extra
fields, so the ai.engine answered 422 and every uploaded scan was stored as `failed`.
`test_ai_engine_client.py` now pins which path the client requests; this pins that
`analyze_scan` wires the three stages together around it.

**Needs PostgreSQL.** `analyze_scan` takes its session from the module-level
`get_sessionmaker()` and `persist_findings` runs real dedupe queries, so faking the
database would mostly test the fakes. Same posture as `test_runs.py`: written now,
skipped until `RUN_INTEGRATION_TESTS=1` with a database, which `make up` provides.

Redis is *not* required. `POST /scans` enqueues an arq job, so that one call is
patched out - queueing is not the gap being covered here.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from cyber_contracts import (
    AgentKind,
    FindingBatch,
    FindingCreate,
    FindingType,
    ScanStatus,
    Severity,
    VulnerabilityAnalyzeRequest,
)
from httpx import AsyncClient
from sqlalchemy import select

from app.db.session import get_sessionmaker
from app.models.finding import Finding
from app.models.scan import Scan
from app.services.ai_engine.client import AiEngineError
from app.tasks import scan_tasks
from tests.conftest import requires_database

pytestmark = requires_database

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def fixture_text(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


class _FakeEngine:
    """Stands in for AiEngineClient, recording what the task sent it."""

    def __init__(self, batch: FindingBatch | Exception) -> None:
        self.batch = batch
        self.requests: list[VulnerabilityAnalyzeRequest] = []
        self.closed = False

    async def assess_vulnerability(
        self, request: VulnerabilityAnalyzeRequest
    ) -> FindingBatch:
        self.requests.append(request)
        if isinstance(self.batch, Exception):
            raise self.batch
        return self.batch

    async def aclose(self) -> None:
        self.closed = True


CANDIDATE_ID = "cand_ssh22"


def _finding(title: str = "Outdated OpenSSH on 10.0.0.5:22") -> FindingCreate:
    """A finding on 10.0.0.5:22, which nmap-basic.xml reports as up with 22 open.

    It carries a ``candidate_id`` because that is what verification joins on -
    content-addressed and stable across runs, so the same fact keeps the same id.
    A finding without one is unverifiable by design.
    """
    return FindingCreate(
        agent=AgentKind.vulnerability,
        finding_type=FindingType.outdated_service,
        title=title,
        description="OpenSSH 7.2 is below the supported baseline.",
        severity=Severity.medium,
        confidence=0.8,
        source="nmap",
        asset="10.0.0.5",
        service="ssh",
        port=22,
        protocol="tcp",
        evidence={"candidate_id": CANDIDATE_ID, "fact": "OpenSSH 7.2 on 10.0.0.5:22."},
        detected_at=datetime.now(UTC),
    )


def _install(
    monkeypatch: pytest.MonkeyPatch, result: FindingBatch | Exception
) -> _FakeEngine:
    """Intercept the client the task builds for itself.

    `analyze_scan` constructs `AiEngineClient()` directly rather than receiving it by
    injection, so `app.dependency_overrides` - the pattern test_discovery.py uses -
    does not reach it. The class has to be replaced on the task module.
    """
    fake = _FakeEngine(result)
    monkeypatch.setattr(scan_tasks, "AiEngineClient", lambda *a, **kw: fake)
    return fake


async def _store(content: str, *, scan_format: str = "nmap_xml", asset: str | None = None) -> UUID:
    """Insert a pending scan row the way the upload endpoint does."""
    factory = get_sessionmaker()
    async with factory() as session:
        scan = Scan(
            filename="test.xml",
            format=scan_format,
            size_bytes=len(content.encode()),
            sha256=f"{uuid4().hex}{uuid4().hex}"[:64],
            asset=asset,
            status=ScanStatus.pending.value,
            raw_content=content,
        )
        session.add(scan)
        await session.commit()
        await session.refresh(scan)
        return scan.id


async def _reload(scan_id: UUID) -> Scan:
    factory = get_sessionmaker()
    async with factory() as session:
        scan = await session.get(Scan, scan_id)
        assert scan is not None
        return scan


async def _findings_for(scan_id: UUID) -> list[Finding]:
    factory = get_sessionmaker()
    async with factory() as session:
        rows = await session.execute(select(Finding).where(Finding.scan_id == scan_id))
        return list(rows.scalars().all())


# ------------------------------------------------------------ the happy path --


async def test_a_parsed_scan_is_assessed_and_persisted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _install(monkeypatch, FindingBatch(agent=AgentKind.vulnerability, findings=[_finding()]))
    scan_id = await _store(fixture_text("nmap-basic.xml"), asset="10.0.0.5")

    result = await scan_tasks.analyze_scan({"job_id": "job-1"}, str(scan_id))

    assert result["status"] == ScanStatus.completed.value
    scan = await _reload(scan_id)
    assert scan.status == ScanStatus.completed.value
    assert scan.host_count > 0
    assert scan.finding_count == 1
    assert scan.completed_at is not None
    assert scan.error is None
    assert fake.closed, "the client must be closed even on the happy path"


async def test_findings_are_stamped_with_their_scan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Without this an analyst cannot trace a finding back to the upload."""
    _install(monkeypatch, FindingBatch(agent=AgentKind.vulnerability, findings=[_finding()]))
    scan_id = await _store(fixture_text("nmap-basic.xml"))

    await scan_tasks.analyze_scan({}, str(scan_id))

    findings = await _findings_for(scan_id)
    assert len(findings) == 1
    assert findings[0].scan_id == scan_id
    assert findings[0].raw_reference == f"scan://{scan_id}"


async def test_the_parsed_scan_crosses_the_wire_not_the_raw_xml(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Parsing lives in the backend, which is why /assess exists at all."""
    fake = _install(monkeypatch, FindingBatch(agent=AgentKind.vulnerability, findings=[]))
    scan_id = await _store(fixture_text("nmap-basic.xml"), asset="10.0.0.5")

    await scan_tasks.analyze_scan({}, str(scan_id))

    assert len(fake.requests) == 1
    request = fake.requests[0]
    assert request.scan_id == scan_id
    assert request.asset == "10.0.0.5"
    assert request.scan.host_count > 0
    assert "sha256" in request.context


# ----------------------------------------------------------- failing loudly --


async def test_an_unparseable_scan_fails_with_a_reason_and_no_findings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A partially-assessed scan must not look done."""
    fake = _install(monkeypatch, FindingBatch(agent=AgentKind.vulnerability, findings=[_finding()]))
    scan_id = await _store(fixture_text("nmap-malformed.xml"))

    result = await scan_tasks.analyze_scan({}, str(scan_id))

    assert result["status"] == ScanStatus.failed.value
    scan = await _reload(scan_id)
    assert scan.status == ScanStatus.failed.value
    assert scan.error
    assert "parse" in scan.error.lower()
    assert await _findings_for(scan_id) == []
    assert fake.requests == [], "the ai.engine must not be called with an unparsed scan"


async def test_an_empty_scan_row_fails_rather_than_crashing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install(monkeypatch, FindingBatch(agent=AgentKind.vulnerability, findings=[]))
    scan_id = await _store("")

    result = await scan_tasks.analyze_scan({}, str(scan_id))

    assert result["status"] == ScanStatus.failed.value
    scan = await _reload(scan_id)
    assert scan.error is not None
    assert "no content" in scan.error.lower()


async def test_an_upstream_failure_records_its_status_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The 422 this whole flow used to hit would have surfaced exactly like this."""
    fake = _install(
        monkeypatch, AiEngineError("the contract was rejected", status_code=422)
    )
    scan_id = await _store(fixture_text("nmap-basic.xml"))

    result = await scan_tasks.analyze_scan({}, str(scan_id))

    assert result["status"] == ScanStatus.failed.value
    scan = await _reload(scan_id)
    assert scan.error is not None
    assert "upstream status 422" in scan.error
    assert await _findings_for(scan_id) == []
    assert fake.closed, "the client must be closed even when the call fails"


async def test_a_missing_scan_is_reported_not_raised(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A deleted scan must not make the job retry forever."""
    _install(monkeypatch, FindingBatch(agent=AgentKind.vulnerability, findings=[]))

    result = await scan_tasks.analyze_scan({}, str(uuid4()))

    assert result["status"] == "missing"


# ------------------------------------------------------------- progression --


async def test_the_status_advances_through_every_stage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Committing at each step is the only reason the frontend's poll shows progress.

    Observed by watching the row from inside the fake engine, which the task calls
    after it has committed `analyzing`.
    """
    seen: list[str] = []
    scan_id = await _store(fixture_text("nmap-basic.xml"))

    class _Watcher(_FakeEngine):
        async def assess_vulnerability(
            self, request: VulnerabilityAnalyzeRequest
        ) -> FindingBatch:
            factory = get_sessionmaker()
            async with factory() as session:
                row = await session.get(Scan, scan_id)
                assert row is not None
                seen.append(row.status)
            return await super().assess_vulnerability(request)

    watcher = _Watcher(FindingBatch(agent=AgentKind.vulnerability, findings=[_finding()]))
    monkeypatch.setattr(scan_tasks, "AiEngineClient", lambda *a, **kw: watcher)

    await scan_tasks.analyze_scan({}, str(scan_id))

    assert seen == [ScanStatus.analyzing.value]
    assert (await _reload(scan_id)).status == ScanStatus.completed.value


# ------------------------------------------------------------ upload route --


async def test_the_upload_route_stores_a_pending_scan(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The half before the worker: sniffing, hashing and the pending row.

    The enqueue is patched out so this needs no Redis - queueing is not the gap.
    """

    async def _no_queue(redis_url: str, scan_id: UUID) -> str:
        del redis_url, scan_id
        return "job-stub"

    monkeypatch.setattr(scan_tasks, "enqueue_scan_analysis", _no_queue)
    monkeypatch.setattr(
        "app.api.v1.endpoints.scans.enqueue_scan_analysis", _no_queue, raising=False
    )

    content = fixture_text("nmap-basic.xml")
    response = await client.post(
        "/scans",
        files={"file": ("nmap-basic.xml", content.encode(), "text/xml")},
        data={"asset": "10.0.0.5"},
    )

    assert response.status_code == 202
    body = response.json()
    assert body["status"] == ScanStatus.pending.value
    assert body["format"] == "nmap_xml"
    assert body["size_bytes"] == len(content.encode())
    assert body["asset"] == "10.0.0.5"
    # raw_content is deliberately absent from ScanRead: up to 5 MB per poll.
    assert "raw_content" not in body


# ----------------------------------------------------------- verification --


async def _scan_without_ssh() -> str:
    """The basic fixture with port 22 removed: a remediated host."""
    content = fixture_text("nmap-basic.xml")
    start = content.find('<port protocol="tcp" portid="22"')
    if start == -1:  # pragma: no cover - guards the fixture, not the code
        raise AssertionError("nmap-basic.xml no longer has a port 22 to remove")
    end = content.find("</port>", start) + len("</port>")
    return content[:start] + content[end:]


async def test_a_finding_resolves_when_a_later_scan_covers_it_and_it_is_gone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The loop, end to end: fix it, re-upload, and it closes with an audit trail."""
    _install(monkeypatch, FindingBatch(agent=AgentKind.vulnerability, findings=[_finding()]))
    first = await _store(fixture_text("nmap-basic.xml"))
    await scan_tasks.analyze_scan({}, str(first))

    stored = (await _findings_for(first))[0]
    assert stored.status == ScanStatus.pending.value or stored.status == "new"

    # A second scan of the same host with the service gone, and nothing found.
    _install(monkeypatch, FindingBatch(agent=AgentKind.vulnerability, findings=[]))
    second = await _store(await _scan_without_ssh())
    await scan_tasks.analyze_scan({}, str(second))

    reloaded = await _reload_finding(stored.id)
    assert reloaded.status == "resolved"
    history = reloaded.evidence["verification"]
    assert history[-1]["outcome"] == "resolved"
    assert str(second) in history[-1]["source"]


async def test_a_finding_stays_open_when_the_later_scan_found_the_host_down(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The failure mode the design exists to prevent, exercised for real."""
    _install(monkeypatch, FindingBatch(agent=AgentKind.vulnerability, findings=[_finding()]))
    first = await _store(fixture_text("nmap-basic.xml"))
    await scan_tasks.analyze_scan({}, str(first))
    stored = (await _findings_for(first))[0]

    down = fixture_text("nmap-basic.xml").replace('<status state="up"', '<status state="down"', 1)
    _install(monkeypatch, FindingBatch(agent=AgentKind.vulnerability, findings=[]))
    second = await _store(down)
    await scan_tasks.analyze_scan({}, str(second))

    reloaded = await _reload_finding(stored.id)
    assert reloaded.status != "resolved", "an offline host must not close findings"
    assert reloaded.evidence["verification"][-1]["outcome"] == "unverified"


async def test_a_finding_still_present_in_a_later_scan_stays_open(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install(monkeypatch, FindingBatch(agent=AgentKind.vulnerability, findings=[_finding()]))
    first = await _store(fixture_text("nmap-basic.xml"))
    await scan_tasks.analyze_scan({}, str(first))
    stored = (await _findings_for(first))[0]

    # The same finding again, carrying the same candidate id.
    _install(monkeypatch, FindingBatch(agent=AgentKind.vulnerability, findings=[_finding()]))
    second = await _store(fixture_text("nmap-basic.xml"))
    await scan_tasks.analyze_scan({}, str(second))

    reloaded = await _reload_finding(stored.id)
    assert reloaded.status != "resolved"
    assert reloaded.evidence["verification"][-1]["outcome"] == "still_present"


async def _reload_finding(finding_id: UUID) -> Finding:
    factory = get_sessionmaker()
    async with factory() as session:
        row = await session.get(Finding, finding_id)
        assert row is not None
        await session.refresh(row)
        return row


async def test_an_unrecognised_upload_is_refused(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def _no_queue(redis_url: str, scan_id: UUID) -> str:
        del redis_url, scan_id
        return "job-stub"

    monkeypatch.setattr(
        "app.api.v1.endpoints.scans.enqueue_scan_analysis", _no_queue, raising=False
    )

    response = await client.post(
        "/scans", files={"file": ("notes.txt", b"just some prose", "text/plain")}
    )

    assert response.status_code == 415
