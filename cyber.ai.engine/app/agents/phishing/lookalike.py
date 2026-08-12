"""Deciding whether a domain is pretending to be another one.

Four distinct tricks, each needing a different test, and all four are used by
``rules/identity.py`` and ``rules/urls.py``:

* **Typosquatting** - ``paypa1.com``, ``micosoft.com``. Caught by edit distance.
* **Homoglyphs** - ``pаypal.com`` with a Cyrillic ``а``. Edit distance does not see
  this at all, because the string genuinely differs by one character that happens to
  render identically. Caught by folding confusables to ASCII first.
* **Punycode** - ``xn--pypal-4ve.com``. The wire form of a homoglyph domain. Decoded
  before comparison, and the mere presence of ``xn--`` in mail from a claimed
  household brand is itself worth reporting.
* **Subdomain impersonation** - ``paypal.com.secure-login.tld``. Nothing is misspelled;
  the real domain is just not where the reader looks. Caught structurally.

**True negatives matter as much as true positives here.** ``paypal.co.uk`` and
``mail.paypal.com`` are legitimate, and a rule that flags them trains an analyst to
ignore the whole category. Every function below is written to be quiet about them,
and the tests assert that explicitly.

No dependencies: the edit distance is 25 lines and ``idna`` decoding is in the
standard library. Pulling in a confusables package would mean shipping a 30,000-entry
Unicode table to solve a problem that a curated map of the scripts actually used in
phishing solves better.
"""

from __future__ import annotations

import ipaddress
import unicodedata
from typing import Final

# Confusables that appear in real phishing, folded to what they imitate. Curated
# rather than exhaustive: Cyrillic and Greek lookalikes for Latin letters, plus the
# digit-for-letter substitutions typosquatters use. A full Unicode confusables table
# would fold thousands of pairs nobody has ever used in a phishing domain.
_CONFUSABLES: Final[dict[str, str]] = {
    # Cyrillic
    "а": "a", "в": "b", "с": "c", "е": "e", "ѕ": "s", "һ": "h", "і": "i", "ј": "j",
    "к": "k", "м": "m", "о": "o", "р": "p", "т": "t", "у": "y", "х": "x", "ԁ": "d",
    "ɡ": "g", "ո": "n", "ս": "u", "ѡ": "w", "ᴜ": "u",
    # Greek
    "α": "a", "β": "b", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p",
    "τ": "t", "υ": "u", "χ": "x", "ϲ": "c", "ϳ": "j",
    # Latin variants and digits used as letters
    "ł": "l", "ø": "o", "đ": "d", "ƚ": "l", "ı": "i", "0": "o", "1": "l", "3": "e",
    "4": "a", "5": "s", "7": "t", "8": "b", "9": "g",
    # Full-width forms
    "ａ": "a", "ｅ": "e", "ｉ": "i", "ｏ": "o", "ｐ": "p", "ｓ": "s",
}

# Suffixes needed to compare registrable domains without shipping the Public Suffix
# List. Only multi-label suffixes go here - a single-label TLD is handled by the
# general case. Incomplete by design, and the failure mode is a slightly wrong
# registrable domain for an unlisted ccTLD, which costs precision, not safety.
_MULTI_LABEL_SUFFIXES: Final[frozenset[str]] = frozenset({
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "sch.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "net.nz", "org.nz",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
    "com.br", "net.br", "org.br", "gov.br",
    "co.za", "org.za", "net.za",
    "com.cn", "net.cn", "org.cn", "gov.cn",
    "co.in", "net.in", "org.in", "gov.in",
    "com.mx", "com.ar", "com.tr", "com.sg", "com.hk", "com.tw", "com.my",
    "com.ph", "com.vn", "com.pl", "com.ua", "co.kr", "or.kr",
})

MAX_LOOKALIKE_DISTANCE: Final = 2
"""Edit distance at which two registrable domains are "confusably similar".

2 catches ``paypa1.com`` (1) and ``micosoft.com`` (1-2) while leaving genuinely
different short brands apart. Raising it to 3 starts matching unrelated four-letter
domains, which is where the false-positive rate stops being worth it."""

MIN_COMPARABLE_LENGTH: Final = 4
"""Below this, edit distance is meaningless - almost any two three-letter labels are
within 2 of each other, so short brands are compared only for exact confusable
matches."""


def fold_confusables(value: str) -> str:
    """Rewrite a string to what it *looks* like in ASCII.

    NFKC first, which collapses full-width and compatibility forms, then the curated
    map. The result is a comparison key only - never stored, never shown, and never
    substituted for the original, because the original is the evidence.
    """
    normalised = unicodedata.normalize("NFKC", value.lower())
    return "".join(_CONFUSABLES.get(char, char) for char in normalised)


def decode_punycode(host: str) -> str:
    """Decode any ``xn--`` labels to their Unicode form.

    Per label rather than whole-host, because a host can mix encoded and plain labels
    and ``idna`` refuses some hosts wholesale that decode fine label by label.
    """
    labels: list[str] = []
    for label in host.split("."):
        if label.startswith("xn--"):
            try:
                labels.append(label.encode("ascii").decode("idna"))
                continue
            except (UnicodeError, UnicodeDecodeError):
                pass  # Undecodable: keep the raw label, which is itself the evidence.
        labels.append(label)
    return ".".join(labels)


def has_punycode(host: str) -> bool:
    """Does this host use punycode at all?"""
    return any(label.startswith("xn--") for label in host.lower().split("."))


def scripts_of(value: str) -> set[str]:
    """Which Unicode scripts a string draws on, by character-name prefix.

    ``unicodedata`` exposes no script property, but the name of every letter starts
    with its script, so the first word of the name is a serviceable proxy.
    """
    found: set[str] = set()
    for char in value:
        if not char.isalpha():
            continue
        try:
            name = unicodedata.name(char)
        except ValueError:
            continue
        found.add(name.split()[0])
    return found


def is_mixed_script(host: str) -> bool:
    """Does this host mix scripts within one label?

    Per label, not per host: ``münchen.example.com`` is one Latin label plus ASCII
    ones and is perfectly ordinary, while ``pаypal`` mixing Latin and Cyrillic inside
    a single label has no legitimate explanation.
    """
    for label in decode_punycode(host).split("."):
        scripts = scripts_of(label)
        if len(scripts) > 1 and scripts != {"LATIN"}:
            return True
    return False


def registrable_domain(host: str) -> str:
    """The domain someone registered, e.g. ``paypal.co.uk`` from ``mail.paypal.co.uk``.

    Needed so ``mail.paypal.com`` compares equal to ``paypal.com`` rather than looking
    like a near-miss.

    **An IP literal is returned unchanged.** An address has no registrable domain, and
    label-slicing one produces nonsense: ``45.61.188.203`` came back as ``188.203``,
    which then appeared verbatim in an analyst-facing sentence claiming a link "points
    to '188.203'". Callers that group or compare by registrable domain want the whole
    address here.
    """
    cleaned = host.lower().strip().strip("[]")
    try:
        ipaddress.ip_address(cleaned)
    except ValueError:
        pass
    else:
        return cleaned

    labels = [label for label in cleaned.strip(".").split(".") if label]
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in _MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def damerau_levenshtein(left: str, right: str) -> int:
    """Edit distance counting insertion, deletion, substitution and transposition.

    Transposition matters: ``paypla.com`` is one swap from ``paypal.com`` and a plain
    Levenshtein distance scores it 2, the same as two unrelated edits.
    """
    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)

    previous: list[int] = []
    current = list(range(len(right) + 1))

    for i, left_char in enumerate(left, start=1):
        before_previous, previous, current = previous, current, [i] + [0] * len(right)
        for j, right_char in enumerate(right, start=1):
            cost = 0 if left_char == right_char else 1
            current[j] = min(
                previous[j] + 1,          # deletion
                current[j - 1] + 1,       # insertion
                previous[j - 1] + cost,   # substitution
            )
            if (
                i > 1
                and j > 1
                and left_char == right[j - 2]
                and left[i - 2] == right_char
            ):
                current[j] = min(current[j], before_previous[j - 2] + cost)

    return current[len(right)]


def is_lookalike(host: str, legitimate: str) -> tuple[bool, str]:
    """Is ``host`` imitating ``legitimate``, and by which trick?

    Returns ``(False, "")`` when the host *is* the legitimate domain or one of its
    subdomains - the true-negative case that keeps this rule credible.
    """
    candidate = registrable_domain(decode_punycode(host))
    target = registrable_domain(legitimate)

    if not candidate or not target:
        return False, ""

    # Legitimate, or a subdomain of it. Checked first and unconditionally.
    if candidate == target:
        return False, ""

    candidate_folded = fold_confusables(candidate)
    target_folded = fold_confusables(target)

    # Renders identically once confusables are folded: a homoglyph or a digit swap.
    if candidate_folded == target_folded:
        return True, "homoglyph"

    if has_punycode(host) and candidate_folded != target_folded:
        # Only report punycode when it is *also* close to a brand; punycode alone is
        # legitimate for genuinely non-Latin domains.
        if damerau_levenshtein(candidate_folded, target_folded) <= MAX_LOOKALIKE_DISTANCE:
            return True, "punycode"

    # The brand appears as a label but is not the registrable domain:
    # paypal.com.secure-login.tld, or secure-paypal.evil.tld.
    brand_label = target.split(".")[0]
    if len(brand_label) >= MIN_COMPARABLE_LENGTH:
        candidate_labels = candidate_folded.split(".")
        host_labels = fold_confusables(decode_punycode(host)).split(".")
        if brand_label in host_labels and brand_label not in candidate_labels[:1]:
            return True, "brand-in-subdomain"

    # Typosquat. Only for labels long enough that edit distance means something.
    if (
        len(target_folded) >= MIN_COMPARABLE_LENGTH
        and len(candidate_folded) >= MIN_COMPARABLE_LENGTH
    ):
        distance = damerau_levenshtein(candidate_folded, target_folded)
        if 0 < distance <= MAX_LOOKALIKE_DISTANCE:
            return True, "typosquat"

    return False, ""


def find_lookalike(host: str, legitimate_domains: frozenset[str] | set[str]) -> tuple[str, str]:
    """The first legitimate domain ``host`` appears to imitate, and how.

    Returns ``("", "")`` when it imitates none of them, which includes the case where
    it genuinely *is* one of them.
    """
    for legitimate in sorted(legitimate_domains):
        matched, technique = is_lookalike(host, legitimate)
        if matched:
            return legitimate, technique
    return "", ""
