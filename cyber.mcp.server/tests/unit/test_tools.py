"""The security tools, tested without an MCP session.

The decorators live in ``app.server``; the work lives in ``app.tools``, which is
why these can be exercised directly. Two of them - the target allowlist and the
port-spec check - are the difference between a scan tool and a scanning proxy for
whoever can reach the port, so they get the most attention here.
"""

from __future__ import annotations

import asyncio
import itertools
import time

import httpx
import pytest

from app.server import _clean_port_spec
from app.tools import CVE_ID_RE, CveLookup, check_target, classify_exposure, parse_networks
from app.tools import cve as cve_module
from app.tools import exposure as exposure_module
from app.tools import targets as targets_module
from app.tools.targets import normalize_target

DEFAULT_NETWORKS = parse_networks(
    ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "::1/128"]
)


# ------------------------------------------------------------ allowlist --

# What the stub resolver below answers. Nothing in this module may touch real DNS:
# a test whose result depends on someone else's zone file is not a test.
RESOLUTIONS = {
    "server.client.test": ["10.0.0.5"],
    "public.client.test": ["93.184.216.34"],
    "split.client.test": ["10.0.0.5", "93.184.216.34"],
    "dual.client.test": ["2001:db8::5", "10.0.0.5"],
    "v6only.client.test": ["2001:db8::5"],
}


@pytest.fixture(autouse=True)
def stub_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    """Resolve from the table above; anything else fails to resolve.

    Patched in both modules because each imported the name into its own
    namespace, so patching one would silently leave the other on real DNS.
    """

    async def resolve(host: str) -> list[str]:
        if host in RESOLUTIONS:
            return RESOLUTIONS[host]
        raise OSError(f"[Errno -2] Name or service not known: {host!r}")

    monkeypatch.setattr(targets_module, "resolve_addresses", resolve)
    monkeypatch.setattr(exposure_module, "resolve_addresses", resolve)


@pytest.mark.parametrize(
    "target",
    ["127.0.0.1", "10.0.0.5", "172.16.4.4", "192.168.1.1", "localhost", "db.internal", "::1"],
)
async def test_targets_inside_the_allowlist_are_permitted(target: str) -> None:
    assert (await check_target(target, DEFAULT_NETWORKS)).allowed is True


@pytest.mark.parametrize(
    "target",
    [
        "8.8.8.8",  # public
        "1.1.1.1",
        "203.0.113.5",
        "public.client.test",  # resolves, but to an address outside the allowlist
        "no-such-host.test",  # does not resolve at all
        "",
        "   ",
        "not an address",
    ],
)
async def test_targets_outside_the_allowlist_are_refused(target: str) -> None:
    decision = await check_target(target, DEFAULT_NETWORKS)

    assert decision.allowed is False
    assert decision.reason, "a refusal must say why"


async def test_a_hostname_resolving_into_the_allowlist_is_scanned_by_address() -> None:
    """The capability this policy exists to allow: a client names their server.

    The name is not what gets scanned - the address it resolved to is, so DNS
    cannot change the target between the check and the scan.
    """
    decision = await check_target("server.client.test", DEFAULT_NETWORKS)

    assert decision.allowed is True
    assert decision.target == "10.0.0.5"
    assert decision.requested == "server.client.test"
    assert decision.addresses == ("10.0.0.5",)


async def test_a_hostname_resolving_outside_the_allowlist_is_refused_by_address() -> None:
    decision = await check_target("public.client.test", DEFAULT_NETWORKS)

    assert decision.allowed is False
    assert "93.184.216.34" in decision.reason, (
        "the refusal must name the address, not the host alone"
    )


async def test_every_address_a_name_returns_has_to_be_in_scope() -> None:
    """One in-scope address does not authorise the rest of a round-robin.

    Which address a scanner reaches is not ours to choose, so a name that is
    partly out of scope is entirely out of scope.
    """
    decision = await check_target("split.client.test", DEFAULT_NETWORKS)

    assert decision.allowed is False
    assert "93.184.216.34" in decision.reason
    assert set(decision.addresses) == {"10.0.0.5", "93.184.216.34"}


async def test_resolution_can_be_turned_off_entirely() -> None:
    decision = await check_target("server.client.test", DEFAULT_NETWORKS, resolve=False)

    assert decision.allowed is False
    assert "SCAN_RESOLVE_HOSTNAMES" in decision.reason


async def test_a_name_that_does_not_resolve_says_so() -> None:
    decision = await check_target("no-such-host.test", DEFAULT_NETWORKS)

    assert decision.allowed is False
    assert "did not resolve" in decision.reason


async def test_a_dual_stack_name_is_scanned_over_ipv4() -> None:
    networks = parse_networks(["10.0.0.0/8", "2001:db8::/32"])

    decision = await check_target("dual.client.test", networks)

    assert decision.allowed is True
    assert decision.target == "10.0.0.5"
    assert decision.is_ipv6 is False


async def test_an_ipv6_only_name_reports_that_the_scanner_needs_ipv6() -> None:
    decision = await check_target("v6only.client.test", parse_networks(["2001:db8::/32"]))

    assert decision.allowed is True
    assert decision.is_ipv6 is True


async def test_an_empty_allowlist_permits_no_addresses() -> None:
    assert (await check_target("10.0.0.5", [])).allowed is False


async def test_a_malformed_allowlist_entry_narrows_rather_than_widens() -> None:
    """A typo in an env var must fail in the safe direction."""
    networks = parse_networks(["10.0.0.0/8", "not-a-cidr", "192.168.0.0/16"])

    assert len(networks) == 2
    assert (await check_target("172.16.4.4", networks)).allowed is False


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
        # Names are resolved and classified by what they point at.
        ("public.client.test", "internet"),
        ("server.client.test", "internal"),
        # A name that does not resolve is unknown, never optimistically internal.
        ("no-such-host.test", "unknown"),
        ("", "unknown"),
    ],
)
async def test_exposure_is_classified_honestly(asset: str, expected: str) -> None:
    assert (await classify_exposure(asset))["exposure"] == expected


async def test_an_unknown_exposure_says_why() -> None:
    result = await classify_exposure("no-such-host.test")

    assert "did not resolve" in result["reason"]
    assert result["is_ip"] is False


async def test_a_resolved_asset_keeps_the_name_the_analyst_used() -> None:
    """Exposure is worth 22 priority points; a named host must not lose them.

    Before names resolved, `server.client.com` scored `unknown` while the same
    box entered as an address scored `internet` - so how the analyst happened to
    type it changed where it ranked.
    """
    result = await classify_exposure("public.client.test")

    assert result["asset"] == "public.client.test"
    assert result["exposure"] == "internet"
    assert "93.184.216.34" in result["reason"], "the address behind the name must be visible"


async def test_a_name_with_any_public_address_is_internet_exposed() -> None:
    """The most exposed address wins: a host reachable from outside is exposed."""
    assert (await classify_exposure("split.client.test"))["exposure"] == "internet"


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
        # No pacing by default: these tests assert on behaviour, not on timing,
        # and the production interval would only make the suite slower. The
        # pacing itself is asserted on in test_enrichment_lookups.py.
        request_interval_seconds=float(kwargs.get("interval", 0.0)),  # type: ignore[arg-type]
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


@pytest.fixture
def fast_backoff(monkeypatch: pytest.MonkeyPatch) -> None:
    """Collapse the rate-limit wait so a 429 test does not cost a real second."""
    monkeypatch.setattr(cve_module, "_RATE_LIMIT_DEFAULT_WAIT", 0.0)


@pytest.mark.parametrize(
    ("status_code", "expected"),
    [(404, "not-found"), (429, "unavailable"), (500, "unavailable")],
)
@pytest.mark.usefixtures("fast_backoff")
async def test_upstream_failures_are_data_not_exceptions(
    status_code: int, expected: str
) -> None:
    """An agent that cannot enrich must carry on, not abort the assessment."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code, json={})

    result = await _lookup(handler).lookup("CVE-2022-0001")

    assert result["status"] == expected


@pytest.mark.usefixtures("fast_backoff")
async def test_a_rate_limited_lookup_is_retried_once_and_then_succeeds() -> None:
    """The failure this exists for: one assessment's CVEs arrive as a burst.

    Live, ``CVE-2018-15473`` was enriched and ``CVE-2019-0211`` came back 429 in
    the same run - two findings from the same scan, one with a CVSS score and one
    without, for no reason to do with either.
    """
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(429, headers={"retry-after": "1"}, json={})
        return httpx.Response(200, json={"summary": "Enriched on the retry.", "cvss3": 7.5})

    result = await _lookup(handler).lookup("CVE-2019-0211")

    assert calls == 2
    assert result["status"] == "ok"
    assert result["cvss"] == 7.5


@pytest.mark.usefixtures("fast_backoff")
async def test_a_persistent_rate_limit_says_so_rather_than_a_bare_status_code() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(429, json={})

    result = await _lookup(handler).lookup("CVE-2019-0211")

    # Retried exactly once - a lookup that keeps retrying is an assessment that
    # never finishes.
    assert calls == 2
    assert result["status"] == "unavailable"
    assert "rate-limiting" in result["detail"]


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        ({"retry-after": "2"}, 2.0),
        ({"retry-after": "0"}, 1.0),
        ({"retry-after": "600"}, 5.0),
        ({"retry-after": "Wed, 21 Oct 2015 07:28:00 GMT"}, 1.0),
        ({}, 1.0),
    ],
)
def test_retry_after_is_honoured_but_clamped(
    header: dict[str, str], expected: float
) -> None:
    """A service may ask for a ten-minute pause; an assessment cannot wait for it."""
    response = httpx.Response(429, headers=header)

    assert cve_module._retry_after_seconds(response) == expected


async def test_requests_are_spaced_out_rather_than_bursting() -> None:
    """Pacing is what stops the 429 happening in the first place."""
    started: list[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        started.append(time.monotonic())
        return httpx.Response(200, json={"summary": "ok"})

    lookup = _lookup(handler, interval=0.05)
    await asyncio.gather(
        *(lookup.lookup(f"CVE-2022-000{index}") for index in range(1, 4))
    )

    assert len(started) == 3
    gaps = [second - first for first, second in itertools.pairwise(started)]
    assert all(gap >= 0.04 for gap in gaps), gaps


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
