"""Lookalike-domain tests.

The true negatives are as important as the positives. `paypal.co.uk` and
`mail.paypal.com` are legitimate, and a rule that flags them teaches an analyst to
ignore the whole category - which costs more than missing one typosquat.
"""

from __future__ import annotations

import pytest

from app.agents.phishing.lookalike import (
    damerau_levenshtein,
    decode_punycode,
    find_lookalike,
    fold_confusables,
    has_punycode,
    is_lookalike,
    is_mixed_script,
    registrable_domain,
)

BRANDS = frozenset({"paypal.com", "microsoft.com", "netflix.com", "dhl.com"})


# ---------------------------------------------------------------------------
# primitives
# ---------------------------------------------------------------------------


def test_edit_distance_counts_a_transposition_as_one() -> None:
    """`paypla` is one swap from `paypal`; plain Levenshtein would score it 2."""
    assert damerau_levenshtein("paypla", "paypal") == 1


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        ("paypal", "paypal", 0),
        ("paypa1", "paypal", 1),      # digit for letter
        ("paypall", "paypal", 1),     # doubled letter
        ("payal", "paypal", 1),       # dropped letter
        ("micosoft", "microsoft", 1),
        ("github", "paypal", 6),      # nothing in common
        ("", "abc", 3),
    ],
)
def test_edit_distance(left: str, right: str, expected: int) -> None:
    """Expectations cross-checked against a naive recursive reference.

    The implementation was verified exhaustively over 116,281 pairs from a 4-symbol
    alphabet up to length 4, so these values describe the optimal-string-alignment
    definition rather than whatever the code happens to return.
    """
    assert damerau_levenshtein(left, right) == expected


def test_confusables_fold_to_what_they_look_like() -> None:
    # Cyrillic а, Cyrillic о, and a digit-for-letter swap.
    assert fold_confusables("pаypal") == "paypal"
    assert fold_confusables("micrоsoft") == "microsoft"
    assert fold_confusables("paypa1") == "paypal"


def test_folding_never_mutates_an_already_ascii_brand() -> None:
    """The fold is a comparison key; an honest domain must survive it unchanged."""
    assert fold_confusables("paypal.com") == "paypal.com"


def test_punycode_round_trips_to_its_unicode_form() -> None:
    assert "а" in decode_punycode("xn--pypal-4ve.com")
    assert has_punycode("xn--pypal-4ve.com") is True
    assert has_punycode("paypal.com") is False


def test_undecodable_punycode_is_kept_rather_than_dropped() -> None:
    """A label that will not decode is itself the evidence."""
    assert decode_punycode("xn--!!!invalid.com") == "xn--!!!invalid.com"


def test_mixed_script_is_detected_per_label() -> None:
    assert is_mixed_script("pаypal.com") is True
    assert is_mixed_script("paypal.com") is False
    # An all-Latin non-ASCII label is ordinary, not mixed.
    assert is_mixed_script("münchen.example.com") is False


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("paypal.com", "paypal.com"),
        ("mail.paypal.com", "paypal.com"),
        ("a.b.c.paypal.com", "paypal.com"),
        ("paypal.co.uk", "paypal.co.uk"),
        ("secure.paypal.co.uk", "paypal.co.uk"),
        ("example.com.au", "example.com.au"),
    ],
)
def test_registrable_domain(host: str, expected: str) -> None:
    assert registrable_domain(host) == expected


# ---------------------------------------------------------------------------
# true negatives - the ones that keep the rule credible
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "host",
    [
        "paypal.com",
        "mail.paypal.com",
        "www.paypal.com",
        "notifications.email.paypal.com",
    ],
)
def test_the_real_domain_and_its_subdomains_are_never_lookalikes(host: str) -> None:
    matched, technique = is_lookalike(host, "paypal.com")

    assert matched is False, f"{host} was flagged as {technique}"


def test_a_different_tld_for_the_same_brand_is_not_flagged() -> None:
    """`paypal.co.uk` is a real PayPal domain, and cross-TLD guessing is not our job.

    The brand allowlist in `data/brands.json` is what decides which TLDs are real;
    edit distance must not second-guess it.
    """
    matched, _ = is_lookalike("paypal.co.uk", "paypal.com")

    assert matched is False


def test_an_unrelated_domain_is_not_a_lookalike() -> None:
    assert is_lookalike("github.com", "paypal.com")[0] is False
    assert is_lookalike("corp.internal", "microsoft.com")[0] is False


def test_short_brands_are_not_compared_by_edit_distance() -> None:
    """Almost any two three-letter labels are within 2 edits of each other.

    `dhl.com` vs `dh1.com` still matches, because that is a confusable fold rather
    than an edit-distance hit.
    """
    assert is_lookalike("ups.com", "dhl.com")[0] is False
    assert is_lookalike("dh1.com", "dhl.com") == (True, "homoglyph")


# ---------------------------------------------------------------------------
# the four tricks
# ---------------------------------------------------------------------------


def test_a_digit_substitution_is_caught_as_a_homoglyph() -> None:
    assert is_lookalike("paypa1.com", "paypal.com") == (True, "homoglyph")


def test_a_cyrillic_homoglyph_is_caught() -> None:
    """Edit distance cannot see this: the string really does differ by one character.

    Only folding confusables first makes `pаypal.com` and `paypal.com` comparable.
    """
    matched, technique = is_lookalike("pаypal.com", "paypal.com")

    assert (matched, technique) == (True, "homoglyph")


def test_punycode_of_a_homoglyph_domain_is_caught() -> None:
    matched, technique = is_lookalike("xn--pypal-4ve.com", "paypal.com")

    assert matched is True
    assert technique in {"homoglyph", "punycode", "typosquat"}


def test_a_typosquat_is_caught() -> None:
    assert is_lookalike("micosoft.com", "microsoft.com") == (True, "typosquat")
    assert is_lookalike("paypall.com", "paypal.com") == (True, "typosquat")


def test_brand_in_subdomain_position_is_caught() -> None:
    """Nothing is misspelled - the real domain is just not where the reader looks."""
    matched, technique = is_lookalike("paypal.com.secure-login.tld", "paypal.com")

    assert (matched, technique) == (True, "brand-in-subdomain")


def test_brand_as_a_left_hand_label_of_another_domain_is_caught() -> None:
    matched, technique = is_lookalike("paypal.secure-billing.tld", "paypal.com")

    assert (matched, technique) == (True, "brand-in-subdomain")


# ---------------------------------------------------------------------------
# find_lookalike over a brand set
# ---------------------------------------------------------------------------


def test_find_lookalike_names_the_brand_and_the_technique() -> None:
    brand, technique = find_lookalike("paypa1.com", BRANDS)

    assert brand == "paypal.com"
    assert technique == "homoglyph"


def test_find_lookalike_is_quiet_about_a_legitimate_brand_domain() -> None:
    assert find_lookalike("paypal.com", BRANDS) == ("", "")
    assert find_lookalike("mail.netflix.com", BRANDS) == ("", "")


def test_find_lookalike_is_quiet_about_an_unrelated_domain() -> None:
    assert find_lookalike("corp.example.internal", BRANDS) == ("", "")
