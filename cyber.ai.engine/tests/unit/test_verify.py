"""The verification pass, and the one property it exists to guarantee.

An inconclusive re-check must never be indistinguishable from a clean one. Every
test here is a different way for the check to fail, asserting the same thing: the
report says so, and nothing looks covered. The backend resolves a finding only when
its port appears in ``ports_scanned``, so an honest failure resolves nothing.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import pytest
from cyber_contracts import VerificationReport, VerificationRequest, VerificationTarget
from httpx import AsyncClient

from app.agents.vulnerability import verify as verify_module
from app.agents.vulnerability.verify import MAX_TARGETS, verify
from app.mcp import NMAP_SCAN_TOOL

# A host answering on 22 with an outdated OpenSSH: parses, reachable, one candidate.
SCAN_WITH_SSH = """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94">
  <host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="22"><state state="open"/>
      <service name="ssh" product="OpenSSH" version="7.2"/></port></ports>
  </host>
</nmaprun>"""

# The same host with the scanned port CLOSED: a successful check that observed
# nothing. This is what a remediated host looks like, and it must not read as a
# failed scan. The closed <port> record only appears because verification asks for
# include_closed - with Nmap's --open the whole <host> element is absent.
SCAN_CLEAN = """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94">
  <host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="22"><state state="closed"/>
      <service name="ssh" method="table"/></port></ports>
  </host>
</nmaprun>"""

SCAN_HOST_DOWN = """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94">
  <host><status state="down"/><address addr="10.0.0.5" addrtype="ipv4"/></host>
</nmaprun>"""


class _FakeTools:
    """Stands in for a live MCP session."""

    def __init__(self, result: dict[str, Any], *, offers: bool = True) -> None:
        self.result = result
        self.offers = offers
        self.calls: list[dict[str, Any]] = []

    def has(self, tool: str) -> bool:
        return self.offers and tool == NMAP_SCAN_TOOL

    async def call(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        self.calls.append(arguments)
        return self.result


def _install(monkeypatch: pytest.MonkeyPatch, tools: _FakeTools | None) -> None:
    """Replace the MCP session the pass opens for itself."""

    @asynccontextmanager
    async def _open(*_args: object, **_kwargs: object) -> AsyncIterator[_FakeTools | None]:
        yield tools

    monkeypatch.setattr(verify_module, "open_tools", _open)


def _ok(output: str) -> dict[str, Any]:
    return {"ok": True, "tool": "nmap", "output": output, "error": "", "meta": {}}


def _failed(error: str) -> dict[str, Any]:
    return {"ok": False, "tool": "nmap", "output": "", "error": error, "meta": {}}


def _request(host: str = "10.0.0.5", ports: list[int] | None = None) -> VerificationRequest:
    return VerificationRequest(
        targets=[VerificationTarget(host=host, ports=ports if ports is not None else [22])]
    )


# ------------------------------------------------------- a conclusive check --


async def test_a_reachable_host_reports_the_ports_it_was_asked_to_cover(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install(monkeypatch, _FakeTools(_ok(SCAN_WITH_SSH)))

    report = await verify(_request(ports=[22, 443]))

    coverage = report.coverage_for("10.0.0.5")
    assert coverage is not None
    assert coverage.scan_ok is True
    assert coverage.reachable is True
    assert coverage.ports_scanned == [22, 443]
    assert coverage.covers(22) is True
    assert report.conclusive is True


async def test_the_scan_covers_exactly_the_ports_under_verification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Scanning what is being verified is what makes coverage provable."""
    tools = _FakeTools(_ok(SCAN_WITH_SSH))
    _install(monkeypatch, tools)

    await verify(_request(ports=[443, 22, 22, 8080]))

    assert tools.calls[0]["ports"] == "22,443,8080", "deduplicated and sorted"
    assert tools.calls[0]["target"] == "10.0.0.5"


async def test_the_scan_asks_for_closed_ports(monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression: without this, a remediated host is unverifiable.

    Nmap's --open omits a host from the XML entirely when none of its scanned ports
    are open. A genuinely fixed target therefore parsed as "no host entries" and was
    recorded as "could not verify" - the one case this pass exists to recognise,
    indistinguishable from a failed scan. Caught against a live nmap, not in a unit
    test, which is why the assertion is on the argument rather than the outcome.
    """
    tools = _FakeTools(_ok(SCAN_CLEAN))
    _install(monkeypatch, tools)

    await verify(_request(ports=[5900]))

    assert tools.calls[0]["include_closed"] is True


async def test_a_port_that_was_never_scanned_is_not_covered(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install(monkeypatch, _FakeTools(_ok(SCAN_WITH_SSH)))

    report = await verify(_request(ports=[22]))

    coverage = report.coverage_for("10.0.0.5")
    assert coverage is not None
    assert coverage.covers(22) is True
    assert coverage.covers(443) is False


async def test_a_still_present_service_is_observed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Observed ids come from the same rule engine that created the findings."""
    _install(monkeypatch, _FakeTools(_ok(SCAN_WITH_SSH)))

    report = await verify(_request(ports=[22]))

    assert report.observed_candidate_ids, "the outdated OpenSSH rule should still fire"


async def test_a_remediated_host_is_covered_and_observes_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The case the whole loop exists for, and the one most easily confused with
    a failed scan: the host answered, the port was checked, nothing is there."""
    _install(monkeypatch, _FakeTools(_ok(SCAN_CLEAN)))

    report = await verify(_request(ports=[22]))

    coverage = report.coverage_for("10.0.0.5")
    assert coverage is not None
    assert coverage.covers(22) is True, "a clean result is still a conclusive one"
    assert report.observed_candidate_ids == []
    assert report.conclusive is True


# ----------------------------------------------------- inconclusive checks --


async def test_a_refused_target_covers_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    """The allowlist refusal an operator most needs explained."""
    _install(
        monkeypatch,
        _FakeTools(_failed("8.8.8.8 is outside the configured scan allowlist.")),
    )

    report = await verify(_request(host="8.8.8.8"))

    coverage = report.coverage_for("8.8.8.8")
    assert coverage is not None
    assert coverage.scan_ok is False
    assert coverage.ports_scanned == []
    assert coverage.covers(22) is False
    assert "allowlist" in coverage.detail
    assert report.conclusive is False


async def test_a_missing_scanner_covers_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, _FakeTools(_failed("nmap is not installed on this host")))

    report = await verify(_request())

    coverage = report.coverage_for("10.0.0.5")
    assert coverage is not None
    assert coverage.covers(22) is False
    assert "not installed" in coverage.detail


async def test_an_unreachable_host_covers_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    """The failure mode that would otherwise resolve every finding on the host."""
    _install(monkeypatch, _FakeTools(_ok(SCAN_HOST_DOWN)))

    report = await verify(_request(ports=[22]))

    coverage = report.coverage_for("10.0.0.5")
    assert coverage is not None
    assert coverage.scan_ok is True, "the scanner ran fine"
    assert coverage.reachable is False, "but the host did not answer"
    assert coverage.ports_scanned == []
    assert coverage.covers(22) is False
    assert "did not answer" in coverage.detail
    assert report.conclusive is False


async def test_an_unparseable_scan_covers_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, _FakeTools(_ok("this is not nmap output")))

    report = await verify(_request())

    coverage = report.coverage_for("10.0.0.5")
    assert coverage is not None
    assert coverage.scan_ok is False
    assert coverage.covers(22) is False
    assert coverage.detail


async def test_mcp_unavailable_covers_nothing_and_says_so(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install(monkeypatch, None)

    report = await verify(_request())

    assert report.conclusive is False
    assert report.coverage[0].covers(22) is False
    assert any("unavailable" in note for note in report.notes)
    assert any("No finding can be resolved" in note for note in report.notes)


async def test_a_server_without_the_scan_tool_covers_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install(monkeypatch, _FakeTools(_ok(SCAN_WITH_SSH), offers=False))

    report = await verify(_request())

    assert report.conclusive is False


async def test_one_failing_target_does_not_sink_the_others(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Per-target coverage, so a partial pass still resolves what it did check."""

    class _Selective(_FakeTools):
        async def call(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
            self.calls.append(arguments)
            if arguments["target"] == "10.0.0.9":
                raise RuntimeError("the transport dropped")
            return _ok(SCAN_CLEAN)

    _install(monkeypatch, _Selective(_ok(SCAN_CLEAN)))

    report = await verify(
        VerificationRequest(
            targets=[
                VerificationTarget(host="10.0.0.5", ports=[22]),
                VerificationTarget(host="10.0.0.9", ports=[22]),
            ]
        )
    )

    good = report.coverage_for("10.0.0.5")
    bad = report.coverage_for("10.0.0.9")
    assert good is not None and good.covers(22) is True
    assert bad is not None and bad.covers(22) is False
    assert "dropped" in bad.detail


# ----------------------------------------------------------------- bounds --


async def test_a_truncated_pass_says_what_it_skipped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Silent truncation would let a caller believe it verified hosts it never did."""
    _install(monkeypatch, _FakeTools(_ok(SCAN_CLEAN)))

    report = await verify(
        VerificationRequest(
            targets=[
                VerificationTarget(host=f"10.0.0.{i}", ports=[22])
                for i in range(1, MAX_TARGETS + 6)
            ]
        )
    )

    assert len(report.coverage) == MAX_TARGETS
    assert any("were not checked" in note for note in report.notes)


async def test_a_target_with_no_ports_falls_back_to_the_default_sweep(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """And covers nothing, because no specific port was proven to be checked."""
    tools = _FakeTools(_ok(SCAN_CLEAN))
    _install(monkeypatch, tools)

    report = await verify(_request(ports=[]))

    assert "ports" not in tools.calls[0]
    coverage = report.coverage_for("10.0.0.5")
    assert coverage is not None
    assert coverage.ports_scanned == []
    assert coverage.covers(22) is False


# ------------------------------------------------------------------ route --


async def test_the_route_answers_200_when_nothing_could_be_checked(
    client: AsyncClient,
) -> None:
    """"Could not verify" is a result the backend acts on, not a failed request.

    The autouse ``_no_mcp`` fixture makes this the MCP-unavailable path.
    """
    response = await client.post(
        "/agents/vulnerability/verify",
        json={"targets": [{"host": "10.0.0.5", "ports": [22]}], "context": {}},
    )

    assert response.status_code == 200
    report = VerificationReport.model_validate(response.json())
    assert report.conclusive is False
    assert report.coverage[0].covers(22) is False


async def test_the_route_rejects_unknown_fields(client: AsyncClient) -> None:
    response = await client.post(
        "/agents/vulnerability/verify",
        json={"targets": [{"host": "10.0.0.5", "ports": [22]}], "unexpected": "value"},
    )

    assert response.status_code == 422


async def test_the_route_requires_at_least_one_target(client: AsyncClient) -> None:
    response = await client.post("/agents/vulnerability/verify", json={"targets": []})

    assert response.status_code == 422
