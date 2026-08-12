"""The security tools, tested without an MCP session.

The decorators live in ``app.server``; the work lives in ``app.tools``, which is
why these can be exercised directly. Two of them - the target allowlist and the
port-spec check - are the difference between a scan tool and a scanning proxy for
whoever can reach the port, so they get the most attention here.
"""

from __future__ import annotations

import httpx
import pytest

from app.server import _clean_port_spec
from app.tools import CVE_ID_RE, CveLookup, check_target, classify_exposure, parse_networks
from app.tools.targets import normalize_target

DEFAULT_NETWORKS = parse_networks(
    ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "::1/128"]
)


# ------------------------------------------------------------ allowlist --


@pytest.mark.parametrize(
    "target",
    ["127.0.0.1", "10.0.0.5", "172.16.4.4", "192.168.1.1", "localhost", "db.internal", "::1"],
)
def test_targets_inside_the_allowlist_are_permitted(target: str) -> None:
    assert check_target(target, DEFAULT_NETWORKS).allowed is True


@pytest.mark.parametrize(
    "target",
    [
        "8.8.8.8",  # public
        "1.1.1.1",
        "203.0.113.5",
        "example.com",  # a hostname is never resolved to decide scope
        "scanme.nmap.org",
        "",
        "   ",
        "not an address",
    ],
)
def test_targets_outside_the_allowlist_are_refused(target: str) -> None:
    decision = check_target(target, DEFAULT_NETWORKS)

    assert decision.allowed is False
    assert decision.reason, "a refusal must say why"


def test_a_public_hostname_is_refused_even_if_it_would_resolve_privately() -> None:
    """Resolving a name to decide scope hands the decision to whoever runs DNS.

    The answer can also change between the check and the scan, so a hostname is
    permitted only when it is explicitly local - never because of a lookup.
    """
    decision = check_target("localtest.me", DEFAULT_NETWORKS)

    assert decision.allowed is False
    assert "hostname" in decision.reason


def test_an_empty_allowlist_permits_no_addresses() -> None:
    assert check_target("10.0.0.5", []).allowed is False


def test_a_malformed_allowlist_entry_narrows_rather_than_widens() -> None:
    """A typo in an env var must fail in the safe direction."""
    networks = parse_networks(["10.0.0.0/8", "not-a-cidr", "192.168.0.0/16"])

    assert len(networks) == 2
    assert check_target("172.16.4.4", networks).allowed is False


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("https://10.0.0.5:8443/status", "10.0.0.5"),
        ("http://user:pw@10.0.0.5/", "10.0.0.5"),
        ("10.0.0.5:22", "10.0.0.5"),
        ("[::1]:8080", "::1"),
        ("::1", "::1"),
        ("  10.0.0.5  ", "10.0.0.5"),
    ],
)
def test_targets_are_normalised_before_the_check(raw: str, expected: str) -> None:
    assert normalize_target(raw) == expected


# ----------------------------------------------------------- port specs --


@pytest.mark.parametrize("ports", ["22", "22,80,443", "1-1024", "22,80,8000-8100"])
def test_valid_port_specifications_are_accepted(ports: str) -> None:
    assert _clean_port_spec(ports) is not None


@pytest.mark.parametrize(
    "ports",
    [
        "-oA/tmp/pwned",  # would be read as an nmap flag
        "--script=exploit",
        "22;rm -rf /",
        "22 80 -sS",
        "",
        "22,",
        ",22",
        "1" * 300,
    ],
)
def test_invalid_port_specifications_are_refused(ports: str) -> None:
    """The argv list already blocks shell injection; this blocks flag injection."""
    assert _clean_port_spec(ports) is None


# ------------------------------------------------------------ exposure --


@pytest.mark.parametrize(
    ("asset", "expected"),
    [
        ("8.8.8.8", "internet"),
        ("1.1.1.1", "internet"),
        ("10.0.0.5", "internal"),
        ("192.168.1.1", "internal"),
        ("127.0.0.1", "internal"),
        ("169.254.1.1", "internal"),
        ("::1", "internal"),
        ("db.internal", "internal"),
        ("localhost", "internal"),
        # Unresolved names are unknown, never optimistically internal.
        ("example.com", "unknown"),
        ("", "unknown"),
    ],
)
def test_exposure_is_classified_honestly(asset: str, expected: str) -> None:
    assert classify_exposure(asset)["exposure"] == expected


def test_an_unknown_exposure_says_why() -> None:
    result = classify_exposure("example.com")

    assert "not resolved" in result["reason"]
    assert result["is_ip"] is False


# ----------------------------------------------------------------- cve --


@pytest.mark.parametrize("cve_id", ["CVE-2021-44228", "cve-2021-44228", "CVE-1999-0001"])
def test_cve_ids_are_recognised(cve_id: str) -> None:
    assert CVE_ID_RE.match(cve_id.upper())


def _lookup(handler: object, **kwargs: object) -> CveLookup:
    transport = httpx.MockTransport(handler)  # type: ignore[arg-type]
    return CveLookup(
        httpx.AsyncClient(transport=transport),
        base_url="https://cve.test/api/cve",
        timeout_seconds=1.0,
        ttl_seconds=float(kwargs.get("ttl", 60)),  # type: ignore[arg-type]
    )


async def test_a_malformed_cve_id_never_reaches_the_network() -> None:
    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover
        raise AssertionError("no request should be made")

    result = await _lookup(handler).lookup("not-a-cve")

    assert result["status"] == "invalid"


async def test_a_known_cve_is_summarised() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/CVE-2021-44228")
        return httpx.Response(
            200,
            json={
                "summary": "Log4Shell.",
                "cvss3": 10.0,
                "published": "2021-12-10",
                "known_exploited": True,
                "references": ["https://example.test/1", "https://example.test/2"],
            },
        )

    result = await _lookup(handler).lookup("cve-2021-44228")

    assert result["status"] == "ok"
    assert result["cve_id"] == "CVE-2021-44228"
    assert result["cvss"] == 10.0
    assert result["known_exploited"] is True
    assert len(result["references"]) == 2


async def test_a_cve5_record_is_understood() -> None:
    """Providers differ; the fields are looked for in more than one place."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "containers": {
                    "cna": {
                        "descriptions": [{"lang": "en", "value": "A described flaw."}],
                        "metrics": [{"cvssV3_1": {"baseScore": 7.5}}],
                        "references": [{"url": "https://example.test/advisory"}],
                    }
                }
            },
        )

    result = await _lookup(handler).lookup("CVE-2022-0001")

    assert result["summary"] == "A described flaw."
    assert result["cvss"] == 7.5
    assert result["references"] == ["https://example.test/advisory"]


@pytest.mark.parametrize(
    ("status_code", "expected"),
    [(404, "not-found"), (429, "unavailable"), (500, "unavailable")],
)
async def test_upstream_failures_are_data_not_exceptions(
    status_code: int, expected: str
) -> None:
    """An agent that cannot enrich must carry on, not abort the assessment."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code, json={})

    result = await _lookup(handler).lookup("CVE-2022-0001")

    assert result["status"] == expected


async def test_an_unreachable_service_is_reported_as_unavailable() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("nothing listening")

    result = await _lookup(handler).lookup("CVE-2022-0001")

    assert result["status"] == "unavailable"
    assert "could not be reached" in result["detail"]


async def test_a_non_json_body_is_reported_as_unavailable() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>rate limited</html>")

    result = await _lookup(handler).lookup("CVE-2022-0001")

    assert result["status"] == "unavailable"


async def test_repeated_lookups_are_served_from_cache() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={"summary": "cached", "cvss3": 5.0})

    lookup = _lookup(handler)
    first = await lookup.lookup("CVE-2022-0001")
    second = await lookup.lookup("CVE-2022-0001")

    assert calls == 1
    assert first["cached"] is False
    assert second["cached"] is True
