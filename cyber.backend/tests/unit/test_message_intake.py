"""Message intake tests: the API surface and the worker job.

Both halves run without PostgreSQL or Redis. The API tests stub the session and
the enqueue call; the job tests drive ``analyze_message`` with a fake session and
a fake ai.engine client, because what needs proving is the *state machine* - which
status is written when, and that a failure writes a reason and no verdict.

The verdict assertions matter most. ``verdict is None`` and
``verdict == "clean"`` mean different things - "never analysed" versus "analysed,
nothing found" - and collapsing them would let a failed assessment render in the
UI as a clean bill of health.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from cyber_contracts import (
    AgentKind,
    FindingBatch,
    FindingCreate,
    FindingType,
    MessageStatus,
    MessageVerdict,
    Severity,
)
from httpx import AsyncClient

from app.models.message import Message
from app.tasks import message_tasks
from app.tasks.message_tasks import analyze_message, url_as_message, verdict_for

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def finding(severity: Severity, title: str = "t") -> FindingCreate:
    return FindingCreate(
        agent=AgentKind.phishing,
        finding_type=FindingType.phishing_message,
        title=title,
        description="d",
        severity=severity,
        confidence=0.7,
        source="eml-upload",
        detected_at=datetime.now(UTC),
    )


# ---------------------------------------------------------------------------
# verdict reduction
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("severity", "expected"),
    [
        (Severity.critical, MessageVerdict.phishing),
        (Severity.high, MessageVerdict.phishing),
        (Severity.medium, MessageVerdict.suspicious),
        (Severity.low, MessageVerdict.suspicious),
        (Severity.info, MessageVerdict.clean),
    ],
)
def test_the_verdict_follows_the_most_severe_finding(
    severity: Severity, expected: MessageVerdict
) -> None:
    assert verdict_for([finding(severity)]) is expected


def test_one_severe_finding_is_not_averaged_away() -> None:
    """Nine info findings and one high is a phishing message, not a clean one."""
    findings = [finding(Severity.info, f"info-{index}") for index in range(9)]
    findings.append(finding(Severity.high, "the real one"))

    assert verdict_for(findings) is MessageVerdict.phishing


def test_no_findings_is_clean_not_null() -> None:
    """Reaching this function means analysis succeeded, so "clean" is the answer.

    Null is reserved for "never analysed", which is what a failure leaves behind.
    """
    assert verdict_for([]) is MessageVerdict.clean


# ---------------------------------------------------------------------------
# URL submissions reuse the message shape
# ---------------------------------------------------------------------------


def test_a_submitted_url_becomes_a_message_with_one_link() -> None:
    """So the URL rules are the same code in both paths rather than a second copy."""
    message = url_as_message("https://paypal-secure.example:8443/login?x=1")

    assert message.format.value == "url"
    assert len(message.links) == 1
    assert message.links[0].host == "paypal-secure.example"
    assert message.links[0].scheme == "https"
    assert message.sender.address == ""
    # No headers were submitted, so nothing may claim they authenticated.
    assert message.auth.present is False


def test_a_submitted_url_strips_userinfo_from_the_host() -> None:
    message = url_as_message("https://paypal.com@evil.example/signin")

    assert message.links[0].host == "evil.example"


# ---------------------------------------------------------------------------
# the API surface
# ---------------------------------------------------------------------------


class _FakeSession:
    """Enough AsyncSession for the intake routes: add, commit, refresh."""

    def __init__(self) -> None:
        self.added: list[Any] = []
        self.commits = 0

    def add(self, row: Any) -> None:
        self.added.append(row)

    async def commit(self) -> None:
        self.commits += 1

    async def refresh(self, row: Any) -> None:
        # The database would fill these; the route reads them back afterwards.
        if getattr(row, "id", None) is None:
            row.id = uuid.uuid4()
        for field, default in (
            ("link_count", 0),
            ("attachment_count", 0),
            ("finding_count", 0),
            ("created_at", datetime.now(UTC)),
            ("updated_at", datetime.now(UTC)),
        ):
            if getattr(row, field, None) is None:
                setattr(row, field, default)


@pytest.fixture
def intake(monkeypatch: pytest.MonkeyPatch) -> _FakeSession:
    """Bind the intake routes to a fake session and a no-op enqueue."""
    from app.api.deps import get_session
    from app.api.v1.endpoints import messages as endpoint
    from app.main import app

    session = _FakeSession()

    async def _session_override() -> Any:
        yield session

    async def _enqueue(_redis_url: str, message_id: uuid.UUID, *, enrich: bool = False) -> str:
        del message_id, enrich
        return "job-test-0001"

    app.dependency_overrides[get_session] = _session_override
    monkeypatch.setattr(endpoint, "enqueue_message_analysis", _enqueue)
    yield session
    app.dependency_overrides.pop(get_session, None)


async def test_uploading_a_message_is_accepted_and_queued(
    client: AsyncClient, intake: _FakeSession
) -> None:
    response = await client.post(
        "/messages",
        files={"file": ("email-phish.eml", (FIXTURES / "email-phish.eml").read_bytes())},
    )

    assert response.status_code == 202
    body = response.json()
    assert body["status"] == MessageStatus.pending.value
    assert body["job_id"] == "job-test-0001"
    assert body["format"] == "email_mime"
    # No verdict yet, and that is not the same as clean.
    assert body["verdict"] is None
    assert len(intake.added) == 1


async def test_the_stored_content_round_trips_to_the_submitted_bytes(
    client: AsyncClient, intake: _FakeSession
) -> None:
    """latin-1 storage has to be byte-exact, or the sha256 describes other bytes."""
    raw = (FIXTURES / "email-latin1.eml").read_bytes()

    await client.post("/messages", files={"file": ("email-latin1.eml", raw)})

    stored: Message = intake.added[0]
    assert stored.raw_content is not None
    assert stored.raw_content.encode("latin-1") == raw


async def test_an_empty_upload_is_rejected(client: AsyncClient, intake: _FakeSession) -> None:
    response = await client.post("/messages", files={"file": ("empty.eml", b"   \r\n")})

    assert response.status_code == 400
    assert not intake.added


async def test_a_file_that_is_not_a_message_is_rejected(
    client: AsyncClient, intake: _FakeSession
) -> None:
    """415 at upload beats a failed row the analyst has to go and read."""
    response = await client.post(
        "/messages", files={"file": ("scan.xml", b'<?xml version="1.0"?><nmaprun/>')}
    )

    assert response.status_code == 415
    assert not intake.added


async def test_an_oversized_upload_is_rejected(client: AsyncClient, intake: _FakeSession) -> None:
    oversized = b"From: a@b.example\r\nSubject: big\r\n\r\n" + (b"A" * (2 * 1024 * 1024 + 10))

    response = await client.post("/messages", files={"file": ("big.eml", oversized)})

    assert response.status_code == 413
    assert not intake.added


async def test_submitting_a_url_is_accepted(client: AsyncClient, intake: _FakeSession) -> None:
    response = await client.post("/messages/url", json={"url": "https://paypal-secure.example/x"})

    assert response.status_code == 202
    body = response.json()
    assert body["format"] == "url"
    assert body["submitted_url"] == "https://paypal-secure.example/x"


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/health",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.5/",
        "file:///etc/passwd",
        "javascript:alert(1)",
        "https://paypal.com@evil.example/signin",
    ],
)
async def test_an_unfetchable_url_is_refused(
    client: AsyncClient, intake: _FakeSession, url: str
) -> None:
    response = await client.post("/messages/url", json={"url": url})

    assert response.status_code == 422
    assert not intake.added


async def test_enrichment_is_off_unless_asked_for(
    client: AsyncClient, intake: _FakeSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fetching contacts the suspect host, so the default must be no."""
    from app.api.v1.endpoints import messages as endpoint

    seen: list[bool] = []

    async def _record(_redis_url: str, message_id: uuid.UUID, *, enrich: bool = False) -> str:
        del message_id
        seen.append(enrich)
        return "job-test-0002"

    monkeypatch.setattr(endpoint, "enqueue_message_analysis", _record)

    await client.post("/messages/url", json={"url": "https://a.example/x"})
    await client.post("/messages/url", json={"url": "https://b.example/x", "enrich": True})

    assert seen == [False, True]


async def test_the_url_route_is_not_shadowed_by_the_id_route(client: AsyncClient) -> None:
    """`/messages/url` must not be parsed as a message id.

    The two differ by method today, so nothing collides - but a later GET on
    `/messages/url` would, and this records the ordering requirement.
    """
    paths = list((await client.get("/openapi.json")).json()["paths"])

    assert paths.index("/messages/url") < paths.index("/messages/{message_id}")


# ---------------------------------------------------------------------------
# the worker job
# ---------------------------------------------------------------------------


class _JobSession:
    """A session that hands back one preloaded Message and records commits."""

    def __init__(self, row: Message | None) -> None:
        self.row = row
        self.commits = 0
        self.status_history: list[str] = []

    async def get(self, _model: type[Message], _pk: uuid.UUID) -> Message | None:
        return self.row

    async def commit(self) -> None:
        self.commits += 1
        if self.row is not None:
            self.status_history.append(self.row.status)

    async def __aenter__(self) -> _JobSession:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        return None


def _message_row(**overrides: Any) -> Message:
    row = Message(
        filename="email-phish.eml",
        format="email_mime",
        size_bytes=10,
        sha256="a" * 64,
        status=MessageStatus.pending.value,
        raw_content=(FIXTURES / "email-phish.eml").read_bytes().decode("latin-1"),
    )
    row.id = uuid.uuid4()
    for field, value in overrides.items():
        setattr(row, field, value)
    return row


@pytest.fixture
def job(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Patch the job's session factory, ai.engine client and persistence."""

    def _install(row: Message | None, batch: FindingBatch | Exception) -> _JobSession:
        session = _JobSession(row)

        monkeypatch.setattr(message_tasks, "get_sessionmaker", lambda: (lambda: session))

        class _FakeClient:
            async def assess_phishing(self, _request: Any) -> FindingBatch:
                if isinstance(batch, Exception):
                    raise batch
                return batch

            async def aclose(self) -> None:
                return None

        monkeypatch.setattr(message_tasks, "AiEngineClient", _FakeClient)

        async def _persist(_session: Any, findings: list[FindingCreate]) -> list[FindingCreate]:
            return findings

        monkeypatch.setattr(message_tasks, "persist_findings", _persist)
        return session

    return _install


async def test_the_happy_path_completes_with_a_verdict(job: Any) -> None:
    row = _message_row()
    batch = FindingBatch(agent=AgentKind.phishing, findings=[finding(Severity.high)])
    session = job(row, batch)

    result = await analyze_message({}, str(row.id))

    assert result["status"] == MessageStatus.completed.value
    assert result["verdict"] == MessageVerdict.phishing.value
    assert row.finding_count == 1
    assert row.error is None
    assert row.completed_at is not None
    # Progress was committed as it happened, so a poll sees real transitions.
    assert MessageStatus.parsing.value in session.status_history
    assert MessageStatus.analyzing.value in session.status_history


async def test_parsing_populates_the_denormalised_columns(job: Any) -> None:
    row = _message_row()
    job(row, FindingBatch(agent=AgentKind.phishing, findings=[]))

    await analyze_message({}, str(row.id))

    assert row.sender == "service@paypa1.com"
    assert row.subject is not None and "suspended" in row.subject
    assert row.link_count == 2
    assert row.attachment_count == 1


async def test_an_ai_engine_failure_fails_loudly_with_no_verdict(job: Any) -> None:
    """The decision was to fail loudly. A null verdict is not a clean verdict."""
    from app.services.ai_engine.client import AiEngineError

    row = _message_row()
    job(row, AiEngineError("no API key configured", status_code=503))

    result = await analyze_message({}, str(row.id))

    assert result["status"] == MessageStatus.failed.value
    assert row.verdict is None
    assert row.error is not None
    assert "no API key configured" in row.error
    assert "upstream status 503" in row.error
    # Unset rather than 0: the failure path writes no count at all, and the
    # column's default is applied by the database on insert. What matters is that
    # nothing partial was recorded.
    assert not row.finding_count
    assert row.completed_at is None


async def test_an_unparseable_message_fails_with_the_reason(job: Any) -> None:
    row = _message_row(raw_content="Subject: no sender at all\r\n\r\nbody\r\n")
    job(row, FindingBatch(agent=AgentKind.phishing, findings=[]))

    result = await analyze_message({}, str(row.id))

    assert result["status"] == MessageStatus.failed.value
    assert row.error is not None
    assert "Could not parse the message" in row.error
    assert row.verdict is None


async def test_findings_are_stamped_with_the_message_they_came_from(
    job: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    row = _message_row()
    captured: list[FindingCreate] = []

    async def _capture(_session: Any, findings: list[FindingCreate]) -> list[FindingCreate]:
        captured.extend(findings)
        return findings

    job(row, FindingBatch(agent=AgentKind.phishing, findings=[finding(Severity.medium)]))
    monkeypatch.setattr(message_tasks, "persist_findings", _capture)

    await analyze_message({}, str(row.id))

    assert captured[0].message_id == row.id
    assert captured[0].raw_reference == f"message://{row.id}"


async def test_a_missing_row_is_reported_rather_than_crashing(job: Any) -> None:
    job(None, FindingBatch(agent=AgentKind.phishing, findings=[]))

    result = await analyze_message({}, str(uuid.uuid4()))

    assert result["status"] == "missing"


async def test_a_url_submission_skips_parsing_and_still_completes(job: Any) -> None:
    row = _message_row(
        format="url",
        raw_content=None,
        submitted_url="https://paypal-secure.example/login",
    )
    job(row, FindingBatch(agent=AgentKind.phishing, findings=[finding(Severity.medium)]))

    result = await analyze_message({}, str(row.id))

    assert result["status"] == MessageStatus.completed.value
    assert result["verdict"] == MessageVerdict.suspicious.value
    assert row.link_count == 1
