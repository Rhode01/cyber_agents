"""Submitted-URL validation tests.

This is the operator-input boundary, not the SSRF control - the check that stops a
public hostname resolving to a private address lives in the ai.engine, per
redirect hop. What is tested here is that an obviously unusable submission gets a
422 with a reason instead of failing deep inside a worker.
"""

from __future__ import annotations

import pytest

from app.core.urls import InvalidSubmittedUrlError, validate_submitted_url


@pytest.mark.parametrize(
    "url",
    [
        "https://paypal-secure.example/login",
        "http://45.61.188.203/verify",
        "https://example.test:8443/path?token=ABC#frag",
        "https://xn--pypal-4ve.example/",
    ],
)
def test_public_http_urls_are_accepted(url: str) -> None:
    assert validate_submitted_url(url) == url


def test_case_is_preserved() -> None:
    """Phishing paths are frequently case-significant session tokens.

    Lowercasing the whole URL would change what actually gets fetched.
    """
    url = "https://Example.test/Path/MixedCase?Token=AbC123"

    assert validate_submitted_url(url) == url


def test_surrounding_whitespace_is_trimmed() -> None:
    assert validate_submitted_url("  https://example.test/x  ") == "https://example.test/x"


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("", "a URL is required"),
        ("   ", "a URL is required"),
        ("example.test/path", "only http, https"),
        ("ftp://example.test/x", "only http, https"),
        ("javascript:alert(1)", "only http, https"),
        ("file:///etc/passwd", "only http, https"),
        ("data:text/html;base64,PHNjcmlwdD4=", "only http, https"),
        ("https://", "no host"),
    ],
)
def test_unusable_submissions_are_refused(url: str, expected: str) -> None:
    with pytest.raises(InvalidSubmittedUrlError, match=expected):
        validate_submitted_url(url)


def test_a_url_that_is_too_long_is_refused() -> None:
    with pytest.raises(InvalidSubmittedUrlError, match="limited to 2048"):
        validate_submitted_url("https://example.test/" + "a" * 2100)


def test_control_characters_are_refused() -> None:
    """Header-injection shaped input, kept out of the stored row and the logs."""
    with pytest.raises(InvalidSubmittedUrlError, match="control characters"):
        validate_submitted_url("https://example.test/x\r\nHost: evil.test")


def test_embedded_credentials_are_refused_rather_than_stripped() -> None:
    """`https://paypal.com@evil.tld/` is itself a phishing technique.

    Refused rather than silently rewritten: quietly changing what an analyst asked
    us to look at is worse than telling them why we won't.
    """
    with pytest.raises(InvalidSubmittedUrlError, match="embedded credentials"):
        validate_submitted_url("https://paypal.com@evil.tld/signin")


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:8000/health",
        "http://localhost.localdomain/",
        "http://127.0.0.1/",
        "http://127.1.2.3/",
        "http://[::1]/",
        "http://10.0.0.5/admin",
        "http://192.168.1.1/",
        "http://172.16.4.9/",
        "http://169.254.169.254/latest/meta-data/",
        "http://0.0.0.0/",
        "http://internal.local/",
        "http://api.internal/",
        "http://box.home.arpa/",
    ],
)
def test_local_and_private_targets_are_refused(url: str) -> None:
    """None of these can be a phishing host, and one of them is a metadata pivot.

    `169.254.169.254` is the cloud instance-metadata address; a submission naming
    it is either a mistake or an attempt to make this platform read its own
    credentials. Either way the answer is no.
    """
    with pytest.raises(InvalidSubmittedUrlError):
        validate_submitted_url(url)


def test_a_hostname_is_not_resolved_here() -> None:
    """Resolution belongs next to the connection it protects.

    Resolving now and connecting later is a rebinding window by construction, and
    it would make an API call's latency depend on DNS. A public hostname that
    happens to resolve to a private address is caught in the ai.engine, per hop.
    """
    # Would be refused if this function resolved; accepted because it does not.
    assert validate_submitted_url("https://localtest.me/x") == "https://localtest.me/x"
