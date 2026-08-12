"""Tests for the DNS and RDAP enrichment lookups.

Both are stubbed - no resolver, no registry. What is being tested is the interpretation,
because that is where the mistakes are: a long SPF record split across TXT chunks, a
registry that publishes three different names for "created", a domain that answers with
verification tokens and no policy.

The recurring property is that **failure is a value, never an exception**. These run inside
enrichment, where the contract is that a failed lookup costs detail and nothing else, so a
raise here would take down an assessment that had already succeeded.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest

from app.tools import dnsrecords as dns_module
from app.tools import rdap as rdap_module
from app.tools.dnsrecords import lookup_dns_records
from app.tools.rdap import lookup_domain_age

# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------


@pytest.fixture
def answers(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Stub the resolver with a name -> records table, and force DNS_AVAILABLE on."""

    def install(table: dict[tuple[str, str], list[str]]) -> None:
        async def query(_resolver: object, name: str, record_type: str) -> list[str]:
            return table.get((name, record_type), [])

        monkeypatch.setattr(dns_module, "DNS_AVAILABLE", True)
        monkeypatch.setattr(dns_module, "_query", query)

        # `lookup_dns_records` builds a resolver before querying; with `_query` stubbed the
        # object is never used, so a bare stand-in is enough and keeps dnspython optional.
        class _Resolver:
            timeout = 0.0
            lifetime = 0.0

        monkeypatch.setattr(dns_module, "dns", _fake_dns_module(_Resolver), raising=False)

    return install


def _fake_dns_module(resolver: type) -> type:
    """A stand-in for the `dns` package exposing only `asyncresolver.Resolver`.

    `lookup_dns_records` constructs a resolver before querying. With `_query` stubbed the
    object is never used, so this keeps dnspython genuinely optional for the test run.
    """
    return type("_Mod", (), {"asyncresolver": type("_R", (), {"Resolver": resolver})})


async def test_spf_and_dmarc_are_picked_out_of_the_txt_set(answers: Any) -> None:
    """A domain's TXT records are mostly unrelated verification tokens."""
    answers(
        {
            ("paypal.com", "TXT"): [
                "google-site-verification=abc123",
                "v=spf1 include:_spf.paypal.com -all",
                "MS=ms12345678",
            ],
            ("_dmarc.paypal.com", "TXT"): ["v=DMARC1; p=reject; rua=mailto:d@paypal.com"],
            ("paypal.com", "MX"): ["10 mx1.paypal.com."],
        }
    )

    result = await lookup_dns_records("paypal.com")

    assert result["ok"] is True
    assert result["spf"] == ["v=spf1 include:_spf.paypal.com -all"]
    assert result["dmarc"] == ["v=DMARC1; p=reject; rua=mailto:d@paypal.com"]
    assert result["mx"] == ["10 mx1.paypal.com."]


async def test_a_domain_with_no_policy_is_a_successful_lookup(answers: Any) -> None:
    """Finding nothing is an answer, not a failure.

    The phishing rule depends on this distinction: "publishes no SPF" is the fact that
    makes a claimed `spf=pass` impossible.
    """
    answers({("evil.example", "TXT"): [], ("_dmarc.evil.example", "TXT"): []})

    result = await lookup_dns_records("evil.example")

    assert result["ok"] is True
    assert result["spf"] == []
    assert result["dmarc"] == []


async def test_a_long_spf_record_split_across_chunks_is_rejoined(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    """A TXT record over 255 bytes arrives as several byte strings.

    Joining them with a space - or taking only the first - corrupts the record, and an SPF
    string that no longer starts with `v=spf1` would be dropped entirely.
    """
    monkeypatch.setattr(dns_module, "DNS_AVAILABLE", True)

    class _Item:
        strings = (b"v=spf1 include:a.example ", b"include:b.example -all")

    class _Resolver:
        timeout = 0.0
        lifetime = 0.0

        async def resolve(self, name: str, record_type: str) -> list[_Item]:
            if name == "split.example" and record_type == "TXT":
                return [_Item()]
            return []

    monkeypatch.setattr(
        dns_module,
        "dns",
        type("_Mod", (), {"asyncresolver": type("_R", (), {"Resolver": _Resolver})}),
        raising=False,
    )

    result = await lookup_dns_records("split.example")

    assert result["spf"] == ["v=spf1 include:a.example include:b.example -all"]


async def test_dkim_selectors_that_answer_are_named(answers: Any) -> None:
    answers({("google._domainkey.corp.example", "TXT"): ["v=DKIM1; k=rsa; p=MIGf..."]})

    result = await lookup_dns_records("corp.example")

    assert result["dkim_selectors_found"] == ["google"]
    assert "default" in result["dkim_selectors_tried"]


async def test_no_dkim_selector_found_is_not_a_claim_that_there_is_none(answers: Any) -> None:
    """Selectors are chosen by the sender and cannot be enumerated from DNS.

    Reporting "no DKIM" from a failed sample would be wrong, so the result says what it
    actually tried.
    """
    answers({})

    result = await lookup_dns_records("corp.example")

    assert result["dkim_selectors_found"] == []
    assert "cannot be enumerated" in result["note"]


async def test_a_trailing_dot_and_case_are_normalised(answers: Any) -> None:
    answers({("paypal.com", "TXT"): ["v=spf1 -all"]})

    result = await lookup_dns_records("  PayPal.COM.  ")

    assert result["domain"] == "paypal.com"
    assert result["spf"] == ["v=spf1 -all"]


async def test_an_empty_domain_is_refused() -> None:
    result = await lookup_dns_records("")

    assert result["ok"] is False
    assert "No domain" in result["error"]


async def test_a_missing_dnspython_reports_itself_rather_than_crashing(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    """The dependency is optional so the server still starts without it.

    A missing library should look like unavailable enrichment, not a boot failure that
    takes every other tool with it.
    """
    monkeypatch.setattr(dns_module, "DNS_AVAILABLE", False)

    result = await lookup_dns_records("paypal.com")

    assert result["ok"] is False
    assert "dnspython is not installed" in result["error"]
    # The shape stays consistent, so a caller need not special-case it.
    assert result["spf"] == []
    assert result["mx"] == []


async def test_a_resolver_failure_is_swallowed_into_an_empty_answer(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    """NXDOMAIN, an empty answer and a timeout are all "we learned nothing"."""
    monkeypatch.setattr(dns_module, "DNS_AVAILABLE", True)

    class _Resolver:
        timeout = 0.0
        lifetime = 0.0

        async def resolve(self, name: str, record_type: str) -> list[object]:
            raise RuntimeError("resolver exploded")

    monkeypatch.setattr(
        dns_module,
        "dns",
        type("_Mod", (), {"asyncresolver": type("_R", (), {"Resolver": _Resolver})}),
        raising=False,
    )

    result = await lookup_dns_records("paypal.com")

    assert result["ok"] is True
    assert result["spf"] == []


# ---------------------------------------------------------------------------
# RDAP
# ---------------------------------------------------------------------------


@pytest.fixture
def registry(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Answer the RDAP bootstrap endpoint with a scripted response."""
    original = rdap_module.httpx.AsyncClient

    def install(handler: Any) -> None:
        def factory(*args: object, **kwargs: object) -> httpx.AsyncClient:
            kwargs["transport"] = httpx.MockTransport(handler)
            return original(*args, **kwargs)

        monkeypatch.setattr(rdap_module.httpx, "AsyncClient", factory)

    return install


def rdap_body(created: str, action: str = "registration") -> dict[str, Any]:
    return {
        "objectClassName": "domain",
        "events": [
            {"eventAction": action, "eventDate": created},
            {"eventAction": "last changed", "eventDate": "2026-08-01T00:00:00Z"},
        ],
        "entities": [
            {
                "roles": ["registrar"],
                # RDAP buries the name in vCard's array format: each entry is
                # [field, params, type, value], so "fn" is what carries it.
                "vcardArray": [
                    "vcard",
                    [
                        ["version", {}, "text", "4.0"],
                        ["fn", {}, "text", "Cheap Registrar Ltd"],
                    ],
                ],
            }
        ],
    }


async def test_a_young_domain_reports_its_age(registry: Any) -> None:
    created = (datetime.now(UTC) - timedelta(days=3)).isoformat()
    registry(lambda request: httpx.Response(200, json=rdap_body(created)))

    result = await lookup_domain_age("paypal-secure.example")

    assert result["ok"] is True
    assert result["age_days"] == 3
    assert result["registrar"] == "Cheap Registrar Ltd"


async def test_an_old_domain_reports_a_large_age(registry: Any) -> None:
    registry(lambda request: httpx.Response(200, json=rdap_body("1999-03-15T00:00:00Z")))

    result = await lookup_domain_age("paypal.com")

    assert result["ok"] is True
    assert result["age_days"] > 9000


@pytest.mark.parametrize("action", ["registration", "created", "last changed registration"])
async def test_every_registration_event_name_is_accepted(registry: Any, action: str) -> None:
    """Registries are inconsistent about which name they use."""
    created = (datetime.now(UTC) - timedelta(days=10)).isoformat()
    registry(lambda request: httpx.Response(200, json=rdap_body(created, action=action)))

    result = await lookup_domain_age("new.example")

    assert result["ok"] is True
    assert result["age_days"] == 10


async def test_the_earliest_registration_event_wins(registry: Any) -> None:
    """A domain re-registered later still dates from its first registration."""
    body = {
        "events": [
            {"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"},
            {"eventAction": "created", "eventDate": "2024-06-01T00:00:00Z"},
        ]
    }
    registry(lambda request: httpx.Response(200, json=body))

    result = await lookup_domain_age("old.example")

    assert result["registered"].startswith("2020-01-01")


async def test_a_z_suffixed_timestamp_is_parsed(registry: Any) -> None:
    registry(lambda request: httpx.Response(200, json=rdap_body("2025-01-15T12:30:00Z")))

    result = await lookup_domain_age("x.example")

    assert result["ok"] is True
    assert result["registered"].startswith("2025-01-15")


async def test_a_naive_timestamp_is_treated_as_utc(registry: Any) -> None:
    """Guessing local time would shift the age by hours for no reason."""
    registry(lambda request: httpx.Response(200, json=rdap_body("2025-01-15T12:30:00")))

    result = await lookup_domain_age("x.example")

    assert result["ok"] is True
    assert result["registered"].endswith("+00:00")


async def test_an_unknown_domain_is_a_readable_failure(registry: Any) -> None:
    registry(lambda request: httpx.Response(404, json={}))

    result = await lookup_domain_age("does-not-exist.example")

    assert result["ok"] is False
    assert "No registry has a record" in result["error"]
    assert result["age_days"] is None


async def test_a_rate_limited_registry_is_a_readable_failure(registry: Any) -> None:
    registry(lambda request: httpx.Response(429, text="slow down"))

    result = await lookup_domain_age("paypal.com")

    assert result["ok"] is False
    assert "429" in result["error"]


async def test_a_registry_with_no_registration_event_is_a_failure(registry: Any) -> None:
    """Some ccTLDs deliberately publish no dates. That is not an age of zero."""
    only_changed = {
        "events": [{"eventAction": "last changed", "eventDate": "2026-01-01T00:00:00Z"}]
    }
    registry(lambda request: httpx.Response(200, json=only_changed))

    result = await lookup_domain_age("private.example")

    assert result["ok"] is False
    assert result["age_days"] is None
    assert "no registration date" in result["error"]


async def test_a_non_json_response_is_a_readable_failure(registry: Any) -> None:
    registry(lambda request: httpx.Response(200, text="<html>maintenance</html>"))

    result = await lookup_domain_age("paypal.com")

    assert result["ok"] is False
    assert "not JSON" in result["error"]


async def test_a_transport_failure_is_reported_not_raised(registry: Any) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("timed out", request=request)

    registry(handler)

    result = await lookup_domain_age("paypal.com")

    assert result["ok"] is False
    assert "ConnectTimeout" in result["error"]


async def test_an_empty_domain_is_refused_before_any_request() -> None:
    result = await lookup_domain_age("   ")

    assert result["ok"] is False
    assert "No domain" in result["error"]
