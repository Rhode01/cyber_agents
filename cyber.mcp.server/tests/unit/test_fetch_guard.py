"""Tests for the one tool that deliberately contacts a host an attacker chose.

The resolver is stubbed and the transport is an `httpx.MockTransport`, so nothing here
touches the network - but the client itself is a real `httpx.AsyncClient`, so redirect
handling, streaming and the hop loop are genuinely exercised rather than simulated.

The case that matters most is `test_a_redirect_to_a_private_address_is_refused`. Checking
only the first URL is the mistake the previous implementation made with `curl -s -L`, and a
redirect is exactly how a public-looking link reaches the cloud metadata endpoint.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator

import httpx
import pytest

from app.tools import fetch as fetch_module
from app.tools import targets as targets_module
from app.tools.fetch import MAX_BODY_BYTES, MAX_HOPS, fetch_page
from app.tools.targets import check_fetch_target

# What each hostname resolves to, for the stub. Anything absent resolves to a public
# address, so a test only lists the hosts whose answer it cares about.
RESOLUTIONS: dict[str, list[str]] = {
    "public.example": ["93.184.216.34"],
    "second.example": ["93.184.216.35"],
    "third.example": ["93.184.216.36"],
    "fourth.example": ["93.184.216.37"],
    "fifth.example": ["93.184.216.38"],
    "sixth.example": ["93.184.216.39"],
    "seventh.example": ["93.184.216.40"],
    "internal.example": ["10.0.0.5"],
    "metadata.example": ["169.254.169.254"],
    "loopback.example": ["127.0.0.1"],
    "mapped.example": ["::ffff:127.0.0.1"],
    "split.example": ["93.184.216.34", "127.0.0.1"],
    "nowhere.example": [],
}


@pytest.fixture(autouse=True)
def _stub_resolver(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Resolve names from the table above instead of using DNS."""

    async def resolve(host: str) -> list[str]:
        cleaned = host.strip("[]")
        try:
            import ipaddress

            ipaddress.ip_address(cleaned)
        except ValueError:
            pass
        else:
            return [cleaned]
        if cleaned in RESOLUTIONS:
            return RESOLUTIONS[cleaned]
        return ["93.184.216.34"]

    monkeypatch.setattr(targets_module, "resolve_addresses", resolve)
    yield


@pytest.fixture
def transport(monkeypatch: pytest.MonkeyPatch) -> Callable[[Callable[..., httpx.Response]], None]:
    """Install a MockTransport into the client `fetch_page` builds."""
    original = fetch_module.httpx.AsyncClient

    def install(handler: Callable[[httpx.Request], httpx.Response]) -> None:
        def factory(*args: object, **kwargs: object) -> httpx.AsyncClient:
            kwargs["transport"] = httpx.MockTransport(handler)
            return original(*args, **kwargs)

        monkeypatch.setattr(fetch_module.httpx, "AsyncClient", factory)

    return install


# ---------------------------------------------------------------------------
# check_fetch_target - the policy on its own
# ---------------------------------------------------------------------------


async def test_a_public_address_is_allowed() -> None:
    decision = await check_fetch_target("https://public.example/login")

    assert decision.allowed is True
    assert decision.host == "public.example"
    assert decision.addresses == ("93.184.216.34",)


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("http://127.0.0.1/", "loopback"),
        ("http://127.1.2.3/", "loopback"),
        ("http://[::1]/", "loopback"),
        ("http://10.0.0.5/admin", "private"),
        ("http://192.168.1.1/", "private"),
        ("http://172.16.4.9/", "private"),
        ("http://0.0.0.0/", "unspecified"),
        ("http://169.254.169.254/latest/meta-data/", "link-local"),
    ],
)
async def test_an_address_literal_pointing_inward_is_refused(url: str, expected: str) -> None:
    decision = await check_fetch_target(url)

    assert decision.allowed is False
    assert expected in decision.reason


async def test_the_metadata_endpoint_names_why_it_matters() -> None:
    """The reason string should tell an operator what was nearly reached."""
    decision = await check_fetch_target("http://169.254.169.254/latest/meta-data/iam/")

    assert decision.allowed is False
    assert "metadata" in decision.reason.lower()


async def test_a_hostname_resolving_to_a_private_address_is_refused() -> None:
    """The reason the policy resolves at all: the name looks fine, the answer does not."""
    decision = await check_fetch_target("https://internal.example/status")

    assert decision.allowed is False
    assert "10.0.0.5" in decision.reason


async def test_a_hostname_resolving_to_the_metadata_address_is_refused() -> None:
    decision = await check_fetch_target("https://metadata.example/latest/meta-data/")

    assert decision.allowed is False
    assert "169.254.169.254" in decision.reason


@pytest.mark.parametrize(
    "literal",
    [
        "::ffff:127.0.0.1",       # loopback, mapped
        "::ffff:10.0.0.5",        # private, mapped
        "::ffff:169.254.169.254", # the metadata endpoint, mapped
        "::ffff:192.168.1.1",
        "2002:0a00:0005::1",      # 6to4 wrapping 10.0.0.5
    ],
)
async def test_addresses_wearing_an_ipv6_disguise_are_refused(literal: str) -> None:
    """The obvious bypass: express a private address in a v6 form.

    Asserted on the *outcome* rather than the mechanism. Python 3.12's `ipaddress`
    already evaluates the embedded v4 address, so `_is_forbidden_for_fetch` needs no
    explicit unwrapping - hand-written unwrapping was deleted as unreachable. If a future
    Python narrows those properties, this test fails instead of the guard quietly
    developing a hole.
    """
    decision = await check_fetch_target(f"http://[{literal}]/latest/meta-data/")

    assert decision.allowed is False


async def test_a_hostname_resolving_to_a_mapped_loopback_is_refused() -> None:
    """Same disguise, arriving through DNS rather than in the URL."""
    decision = await check_fetch_target("https://mapped.example/")

    assert decision.allowed is False
    assert "::ffff:127.0.0.1" in decision.reason


async def test_every_resolved_address_must_be_public() -> None:
    """One public and one loopback answer is still a refusal.

    Which address the client would actually connect to is not ours to predict, so a host
    that offers both is refused.
    """
    decision = await check_fetch_target("https://split.example/")

    assert decision.allowed is False
    assert "127.0.0.1" in decision.reason


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost/",
        "http://localhost.localdomain/",
        "http://box.local/",
        "http://api.internal/",
    ],
)
async def test_local_names_are_refused_without_resolving(url: str) -> None:
    """These are local by definition; asking a resolver only invites a surprise."""
    decision = await check_fetch_target(url)

    assert decision.allowed is False
    assert "local" in decision.reason.lower()


@pytest.mark.parametrize(
    "url",
    ["file:///etc/passwd", "javascript:alert(1)", "ftp://public.example/x", "gopher://x.example/"],
)
async def test_only_http_schemes_can_be_fetched(url: str) -> None:
    decision = await check_fetch_target(url)

    assert decision.allowed is False
    assert "http" in decision.reason


async def test_a_host_that_does_not_resolve_is_refused() -> None:
    decision = await check_fetch_target("https://nowhere.example/")

    assert decision.allowed is False
    assert "no addresses" in decision.reason


async def test_an_empty_url_is_refused() -> None:
    assert (await check_fetch_target("")).allowed is False


# ---------------------------------------------------------------------------
# fetch_page - the loop, the caps, and what it extracts
# ---------------------------------------------------------------------------


LOGIN_PAGE = (
    "<html><head><title>Sign in to your account</title>"
    "<script>var x = 1;</script></head><body>"
    "<h1>Sign in</h1><p>Enter your details to continue.</p>"
    '<form action="https://harvest.example/collect">'
    '<input type="text" name="user"><input type="password" name="pass">'
    "</form></body></html>"
)


async def test_a_public_page_is_fetched_and_described(transport: Callable[..., None]) -> None:
    transport(lambda request: httpx.Response(200, text=LOGIN_PAGE))

    outcome = await fetch_page("https://public.example/login")

    assert outcome.ok is True
    assert outcome.status == 200
    assert outcome.final_host == "public.example"
    assert outcome.title == "Sign in to your account"
    assert outcome.password_field is True
    assert outcome.form_hosts == ["harvest.example"]
    assert "Enter your details" in outcome.visible_text
    # Script and style content is not visible text and must not leak into it.
    assert "var x" not in outcome.visible_text


async def test_a_page_without_a_password_field_says_so(transport: Callable[..., None]) -> None:
    transport(lambda request: httpx.Response(200, text="<html><body>Hello</body></html>"))

    outcome = await fetch_page("https://public.example/")

    assert outcome.ok is True
    assert outcome.password_field is False
    assert outcome.form_hosts == []


async def test_a_refused_target_is_never_requested(transport: Callable[..., None]) -> None:
    """The guard runs before the request, not after it."""
    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(str(request.url))
        return httpx.Response(200, text="should not happen")

    transport(handler)

    outcome = await fetch_page("http://169.254.169.254/latest/meta-data/")

    assert outcome.ok is False
    assert requested == [], "a refused target must not reach the transport"


async def test_a_redirect_chain_is_followed_and_recorded(
    transport: Callable[..., None]
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "public.example":
            return httpx.Response(302, headers={"location": "https://second.example/next"})
        return httpx.Response(200, text=LOGIN_PAGE)

    transport(handler)

    outcome = await fetch_page("https://public.example/start")

    assert outcome.ok is True
    assert outcome.final_host == "second.example"
    assert outcome.redirect_chain == ["public.example", "second.example"]


async def test_a_redirect_to_a_private_address_is_refused(
    transport: Callable[..., None]
) -> None:
    """The case a first-URL-only check misses entirely.

    The link looks public. The redirect is where it goes inward - and following redirects
    inside the client, as `curl -L` did, would check only the first hop.
    """
    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(str(request.url))
        if request.url.host == "public.example":
            return httpx.Response(
                302, headers={"location": "http://169.254.169.254/latest/meta-data/"}
            )
        return httpx.Response(200, text="metadata!")

    transport(handler)

    outcome = await fetch_page("https://public.example/start")

    assert outcome.ok is False
    assert "link-local" in outcome.error
    assert len(requested) == 1, "the redirect target must not be requested"


async def test_a_redirect_to_a_private_hostname_is_refused(
    transport: Callable[..., None]
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "public.example":
            return httpx.Response(302, headers={"location": "https://internal.example/admin"})
        return httpx.Response(200, text="internal")

    transport(handler)

    outcome = await fetch_page("https://public.example/start")

    assert outcome.ok is False
    assert "10.0.0.5" in outcome.error


async def test_the_hop_cap_stops_a_redirect_loop(transport: Callable[..., None]) -> None:
    hosts = [
        "public.example",
        "second.example",
        "third.example",
        "fourth.example",
        "fifth.example",
        "sixth.example",
        "seventh.example",
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        current = request.url.host
        index = hosts.index(current) if current in hosts else 0
        nxt = hosts[min(index + 1, len(hosts) - 1)]
        return httpx.Response(302, headers={"location": f"https://{nxt}/next"})

    transport(handler)

    outcome = await fetch_page("https://public.example/start")

    assert outcome.ok is False
    assert f"after {MAX_HOPS} redirects" in outcome.error


async def test_an_enormous_body_is_truncated_not_streamed_forever(
    transport: Callable[..., None]
) -> None:
    oversized = "<html><body>" + ("A" * (MAX_BODY_BYTES * 2)) + "</body></html>"
    transport(lambda request: httpx.Response(200, text=oversized))

    outcome = await fetch_page("https://public.example/")

    assert outcome.ok is True
    assert outcome.truncated is True
    assert outcome.bytes_read == MAX_BODY_BYTES


async def test_a_transport_failure_is_reported_not_raised(
    transport: Callable[..., None]
) -> None:
    """Enrichment must degrade, never raise: a failure costs detail and nothing else."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    transport(handler)

    outcome = await fetch_page("https://public.example/")

    assert outcome.ok is False
    assert "ConnectError" in outcome.error


async def test_a_relative_redirect_is_resolved_against_the_current_url(
    transport: Callable[..., None]
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/start":
            return httpx.Response(302, headers={"location": "/landing"})
        return httpx.Response(200, text=LOGIN_PAGE)

    transport(handler)

    outcome = await fetch_page("https://public.example/start")

    assert outcome.ok is True
    assert outcome.final_url.endswith("/landing")


# ---------------------------------------------------------------------------
# the platform kill switch
# ---------------------------------------------------------------------------


async def test_the_tool_refuses_when_the_platform_switch_is_off(
    monkeypatch: pytest.MonkeyPatch, transport: Callable[..., None]
) -> None:
    """Two switches must agree before any request leaves the host.

    The per-request opt-in alone is not enough: an operator has to be able to disable all
    egress regardless of what a request asks for. Default is off.
    """
    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(str(request.url))
        return httpx.Response(200, text=LOGIN_PAGE)

    transport(handler)

    from app import server
    from app.config import Settings

    disabled = Settings(**{**server.get_settings().model_dump(), "phishing_fetch_enabled": False})
    monkeypatch.setattr(server, "get_settings", lambda: disabled)

    result = await server.fetch_url("https://public.example/login")

    assert result["ok"] is False
    assert "PHISHING_FETCH_ENABLED" in result["error"]
    assert requested == [], "nothing may leave the host while the switch is off"


async def test_the_tool_fetches_when_both_switches_agree(
    monkeypatch: pytest.MonkeyPatch, transport: Callable[..., None]
) -> None:
    transport(lambda request: httpx.Response(200, text=LOGIN_PAGE))

    from app import server
    from app.config import Settings

    enabled = Settings(**{**server.get_settings().model_dump(), "phishing_fetch_enabled": True})
    monkeypatch.setattr(server, "get_settings", lambda: enabled)

    result = await server.fetch_url("https://public.example/login")

    assert result["ok"] is True
    assert result["password_field"] is True


def test_fetching_is_disabled_by_default() -> None:
    """Fetching tells whoever runs the site that the message is being investigated, so
    it should be a decision rather than a side effect."""
    from app.config import Settings

    assert Settings().phishing_fetch_enabled is False
