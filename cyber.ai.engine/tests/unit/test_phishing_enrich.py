"""Tests for phishing enrichment, and the seam between two services.

The result shapes asserted here are the ones `cyber.mcp.server` actually returns. That
makes this the contract test for a boundary no type checker crosses: the ai.engine calls
these tools over MCP by name, with dict results, so a renamed key on the server side would
otherwise surface as enrichment quietly finding nothing.

The invariant under test throughout: **enrichment may only add signal.** Unavailable MCP, a
failed lookup, a disabled policy - each costs detail and never changes a verdict. A
phishing message must not become clean because a DNS query timed out.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import pytest
from cyber_contracts import (
    AuthResults,
    EmailAddress,
    EmailLink,
    EnrichmentPolicy,
    MessageFormat,
    NormalizedMessage,
)

from app.agents.phishing import enrich as enrich_module
from app.agents.phishing.enrich import gather


def message(
    *,
    sender_domain: str = "paypa1.com",
    spf: str = "fail",
    dmarc: str = "fail",
    links: list[EmailLink] | None = None,
) -> NormalizedMessage:
    return NormalizedMessage(
        format=MessageFormat.email_mime,
        sender=EmailAddress(
            display_name="PayPal", address=f"service@{sender_domain}", domain=sender_domain
        ),
        auth=AuthResults(spf=spf, dkim="none", dmarc=dmarc, present=True),
        links=links or [],
    )


class FakeTools:
    """Stands in for `McpTools`, recording calls and returning scripted results."""

    def __init__(
        self, results: dict[str, dict[str, Any]], *, offered: set[str] | None = None
    ) -> None:
        self._results = results
        self._offered = offered if offered is not None else set(results)
        self.calls: list[tuple[str, dict[str, Any]]] = []

    @property
    def available(self) -> frozenset[str]:
        return frozenset(self._offered)

    def has(self, tool: str) -> bool:
        return tool in self._offered

    async def call(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        self.calls.append((tool, arguments))
        return self._results.get(tool, {"ok": False, "error": "not scripted"})


@pytest.fixture
def mcp(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Install a fake MCP session. Pass None to simulate an unreachable server.

    conftest's autouse `_no_mcp` fixture has already forced `open_tools` to yield None by
    the time a test body runs, so calling this re-patches over it. That ordering is what
    lets these tests exercise the available path while every other test keeps the safe
    default of no network.
    """

    def install(tools: FakeTools | None) -> FakeTools | None:
        @asynccontextmanager
        async def opener(*_args: object, **_kwargs: object) -> AsyncIterator[FakeTools | None]:
            yield tools

        monkeypatch.setattr(enrich_module, "open_tools", opener)
        return tools

    return install


# ---------------------------------------------------------------------------
# degraded paths - the invariant
# ---------------------------------------------------------------------------


async def test_an_unreachable_mcp_server_adds_nothing_and_raises_nothing(mcp: Any) -> None:
    mcp(None)

    result = await gather(message=message(), policy=EnrichmentPolicy(), existing=[])

    assert result.indicators == []
    assert result.report["available"] is False
    assert "unreachable" in result.report["reason"]


async def test_a_failed_lookup_adds_no_indicator(mcp: Any) -> None:
    """A DNS failure must not be able to make a phishing message look clean."""
    mcp(FakeTools({"dns_records": {"ok": False, "error": "SERVFAIL", "spf": [], "dmarc": []}}))

    result = await gather(message=message(), policy=EnrichmentPolicy(), existing=[])

    assert result.indicators == []
    assert result.report["available"] is True


async def test_a_server_offering_no_enrichment_tools_is_survivable(mcp: Any) -> None:
    """An older MCP server that predates these tools."""
    tools = mcp(FakeTools({}, offered=set()))

    result = await gather(message=message(), policy=EnrichmentPolicy(), existing=[])

    assert result.indicators == []
    assert tools is not None and tools.calls == []


async def test_nothing_is_looked_up_for_a_message_with_no_domain_or_links(mcp: Any) -> None:
    tools = mcp(FakeTools({}))
    empty = NormalizedMessage(
        format=MessageFormat.url,
        sender=EmailAddress(display_name="", address="", domain=""),
        auth=AuthResults(spf="none", dkim="none", dmarc="none", present=False),
    )

    result = await gather(message=empty, policy=EnrichmentPolicy(), existing=[])

    assert result.report["reason"] == "nothing to look up"
    assert tools is not None and tools.calls == []


# ---------------------------------------------------------------------------
# DNS - checking a claim against what the domain publishes
# ---------------------------------------------------------------------------


async def test_a_claimed_spf_pass_with_no_published_record_is_an_indicator(mcp: Any) -> None:
    """The whole point of the DNS lookup.

    An `spf=pass` header is text the delivery path wrote. If the domain publishes no SPF
    record, no verifier could have produced that result, so the claim was decorative.
    """
    mcp(
        FakeTools(
            {"dns_records": {"ok": True, "spf": [], "dmarc": ["v=DMARC1; p=none"], "mx": []}}
        )
    )

    result = await gather(
        message=message(spf="pass", dmarc="pass"), policy=EnrichmentPolicy(), existing=[]
    )

    rules = {indicator.rule_id for indicator in result.indicators}
    assert "enrich-spf-claim-unsupported" in rules
    found = next(i for i in result.indicators if i.rule_id == "enrich-spf-claim-unsupported")
    assert found.weight >= 0.8


async def test_a_claimed_pass_backed_by_a_real_record_adds_nothing(mcp: Any) -> None:
    mcp(
        FakeTools(
            {
                "dns_records": {
                    "ok": True,
                    "spf": ["v=spf1 include:_spf.paypal.com -all"],
                    "dmarc": ["v=DMARC1; p=reject"],
                    "mx": ["10 mx.paypal.com."],
                }
            }
        )
    )

    result = await gather(
        message=message(sender_domain="paypal.com", spf="pass", dmarc="pass"),
        policy=EnrichmentPolicy(),
        existing=[],
    )

    rules = {indicator.rule_id for indicator in result.indicators}
    assert "enrich-spf-claim-unsupported" not in rules
    assert "enrich-no-dmarc-policy" not in rules


async def test_an_absent_dmarc_policy_is_a_weak_indicator(mcp: Any) -> None:
    """Common among smaller senders, so it must stay weak."""
    mcp(FakeTools({"dns_records": {"ok": True, "spf": ["v=spf1 -all"], "dmarc": [], "mx": []}}))

    result = await gather(
        message=message(spf="none", dmarc="none"), policy=EnrichmentPolicy(), existing=[]
    )

    found = next(i for i in result.indicators if i.rule_id == "enrich-no-dmarc-policy")
    assert found.weight <= 0.45


async def test_dns_is_skipped_when_the_policy_forbids_it(mcp: Any) -> None:
    tools = mcp(FakeTools({"dns_records": {"ok": True, "spf": [], "dmarc": []}}))

    await gather(
        message=message(),
        policy=EnrichmentPolicy(resolve_dns=False, domain_age=False),
        existing=[],
    )

    assert tools is not None
    assert [name for name, _ in tools.calls] == []


async def test_the_registrable_domain_is_what_gets_looked_up(mcp: Any) -> None:
    """`mail.paypa1.com` and `paypa1.com` publish the same policy."""
    tools = mcp(FakeTools({"dns_records": {"ok": True, "spf": [], "dmarc": []}}))

    await gather(
        message=message(sender_domain="mail.paypa1.com"),
        policy=EnrichmentPolicy(domain_age=False),
        existing=[],
    )

    assert tools is not None
    assert tools.calls[0] == ("dns_records", {"domain": "paypa1.com"})


# ---------------------------------------------------------------------------
# domain age
# ---------------------------------------------------------------------------


async def test_a_newly_registered_sender_domain_is_an_indicator(mcp: Any) -> None:
    mcp(
        FakeTools(
            {
                "lookup_domain_age": {
                    "ok": True,
                    "age_days": 3,
                    "registered": "2026-08-09T00:00:00+00:00",
                }
            },
            offered={"lookup_domain_age"},
        )
    )

    result = await gather(message=message(), policy=EnrichmentPolicy(), existing=[])

    found = next(i for i in result.indicators if i.rule_id == "enrich-young-sender-domain")
    assert "3 day" in found.fact
    assert found.evidence["age_days"] == 3


async def test_an_established_domain_adds_nothing(mcp: Any) -> None:
    mcp(
        FakeTools(
            {"lookup_domain_age": {"ok": True, "age_days": 9000, "registered": "1999-03-15"}},
            offered={"lookup_domain_age"},
        )
    )

    result = await gather(message=message(), policy=EnrichmentPolicy(), existing=[])

    assert result.indicators == []


async def test_a_nonsense_age_is_ignored_rather_than_reported(mcp: Any) -> None:
    """A registry answering with a negative or non-numeric age says nothing useful."""
    for bad in (-5, "recently", None):
        mcp(
            FakeTools(
                {"lookup_domain_age": {"ok": True, "age_days": bad}},
                offered={"lookup_domain_age"},
            )
        )

        result = await gather(message=message(), policy=EnrichmentPolicy(), existing=[])

        assert result.indicators == [], f"age_days={bad!r} should be ignored"


# ---------------------------------------------------------------------------
# the fetch - opt-in, and what it establishes
# ---------------------------------------------------------------------------


def phish_links() -> list[EmailLink]:
    return [
        EmailLink(
            url="http://45.61.188.203/paypal/login",
            scheme="http",
            host="45.61.188.203",
            anchor_text="https://www.paypal.com/signin",
        )
    ]


async def test_fetching_is_skipped_and_said_so_when_not_requested(mcp: Any) -> None:
    """Off by default, because fetching tells the phisher they are being investigated."""
    tools = mcp(FakeTools({"fetch_url": {"ok": True}}, offered={"fetch_url"}))

    result = await gather(
        message=message(links=phish_links()),
        policy=EnrichmentPolicy(resolve_dns=False, domain_age=False, fetch_urls=False),
        existing=[],
    )

    assert tools is not None and tools.calls == []
    assert "not requested" in result.report["lookups"]["fetch_url"]["skipped"]


async def test_a_credential_form_at_the_destination_is_a_strong_indicator(mcp: Any) -> None:
    mcp(
        FakeTools(
            {
                "fetch_url": {
                    "ok": True,
                    "final_host": "harvest.example",
                    "redirect_chain": ["45.61.188.203", "harvest.example"],
                    "password_field": True,
                    "title": "Sign in to your account",
                    "form_hosts": ["collect.example"],
                }
            },
            offered={"fetch_url"},
        )
    )

    result = await gather(
        message=message(links=phish_links()),
        policy=EnrichmentPolicy(resolve_dns=False, domain_age=False, fetch_urls=True),
        existing=[],
    )

    found = next(i for i in result.indicators if i.rule_id == "enrich-credential-form")
    assert found.weight >= 0.85
    assert found.evidence["final_host"] == "harvest.example"
    assert found.evidence["title"] == "Sign in to your account"


async def test_a_long_redirect_chain_is_an_indicator(mcp: Any) -> None:
    mcp(
        FakeTools(
            {
                "fetch_url": {
                    "ok": True,
                    "final_host": "end.example",
                    "redirect_chain": ["a.example", "b.example", "c.example", "end.example"],
                    "password_field": False,
                }
            },
            offered={"fetch_url"},
        )
    )

    result = await gather(
        message=message(links=phish_links()),
        policy=EnrichmentPolicy(resolve_dns=False, domain_age=False, fetch_urls=True),
        existing=[],
    )

    found = next(i for i in result.indicators if i.rule_id == "enrich-redirect-chain")
    assert "3 different hosts" in found.fact


async def test_a_refused_fetch_adds_nothing_but_is_recorded(mcp: Any) -> None:
    """The server refusing a target is a normal outcome, not an error to surface."""
    mcp(
        FakeTools(
            {
                "fetch_url": {
                    "ok": False,
                    "error": "metadata.example resolves to 169.254.169.254, which is a "
                    "link-local address.",
                }
            },
            offered={"fetch_url"},
        )
    )

    result = await gather(
        message=message(links=phish_links()),
        policy=EnrichmentPolicy(resolve_dns=False, domain_age=False, fetch_urls=True),
        existing=[],
    )

    assert result.indicators == []
    recorded = result.report["lookups"]["fetch_url"]["results"][0]["result"]
    assert recorded["ok"] is False
    assert "link-local" in recorded["error"]


async def test_the_number_of_fetched_links_respects_the_policy_cap(mcp: Any) -> None:
    tools = mcp(
        FakeTools({"fetch_url": {"ok": True, "password_field": False}}, offered={"fetch_url"})
    )
    many = [
        EmailLink(
            url=f"https://h{n}.example/p",
            scheme="https",
            host=f"h{n}.example",
            anchor_text="",
        )
        for n in range(10)
    ]

    await gather(
        message=message(links=many),
        policy=EnrichmentPolicy(
            resolve_dns=False, domain_age=False, fetch_urls=True, max_urls=3
        ),
        existing=[],
    )

    assert tools is not None
    assert len([name for name, _ in tools.calls if name == "fetch_url"]) == 3


async def test_only_http_links_are_offered_for_fetching(mcp: Any) -> None:
    tools = mcp(
        FakeTools({"fetch_url": {"ok": True, "password_field": False}}, offered={"fetch_url"})
    )
    mixed = [
        EmailLink(url="mailto:a@b.example", scheme="mailto", host="", anchor_text=""),
        EmailLink(url="javascript:alert(1)", scheme="javascript", host="", anchor_text=""),
        EmailLink(
            url="https://real.example/x", scheme="https", host="real.example", anchor_text=""
        ),
    ]

    await gather(
        message=message(links=mixed),
        policy=EnrichmentPolicy(resolve_dns=False, domain_age=False, fetch_urls=True),
        existing=[],
    )

    assert tools is not None
    fetched = [args["url"] for name, args in tools.calls if name == "fetch_url"]
    assert fetched == ["https://real.example/x"]
