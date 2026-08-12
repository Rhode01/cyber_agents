"""The bundled phishing knowledge base.

Four JSON files under ``data/``, loaded once and validated through Pydantic on the
way in. Validation matters more than it looks: a typo in ``brands.json`` that made a
brand's legitimate domain unparseable would not crash anything, it would just stop
the allowlist matching - and the identity rule would then flag every genuine message
from that brand. Failing at import is the loud version of that, and the quiet version
is a detector that cries wolf until someone stops believing it.

Nothing here reaches the network. Live lookups - real DNS policy, domain age, the
page a link actually serves - are enrichment, and they go through the MCP server.
This file is what the agent knows offline, which is also what it falls back to when
enrichment is unavailable.

The confusables map is deliberately **not** here: it lives in ``lookalike.py``,
because it is a comparison primitive rather than tunable knowledge. Moving it into
JSON would invite editing it without running the lookalike tests.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Final

from pydantic import BaseModel, ConfigDict, Field, field_validator

DATA_DIR: Final = Path(__file__).parent / "data"


class Brand(BaseModel):
    """One impersonated brand and the domains that legitimately send its mail."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=1)
    aliases: tuple[str, ...] = Field(min_length=1)
    domains: tuple[str, ...] = Field(min_length=1)

    @field_validator("aliases", "domains")
    @classmethod
    def _lowercase(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        """Both sides of every comparison are lowercased, so normalise on load."""
        return tuple(item.strip().lower() for item in value if item.strip())

    @field_validator("domains")
    @classmethod
    def _reject_subdomains(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        """Domains must be registrable form.

        The rules compare registrable domains, so ``mail.paypal.com`` here would be
        dead weight - and listing *only* a subdomain would make its own parent look
        like an impostor. Caught on load rather than debugged later.
        """
        from app.agents.phishing.lookalike import registrable_domain

        for domain in value:
            if registrable_domain(domain) != domain:
                msg = (
                    f"{domain!r} is not a registrable domain "
                    f"(did you mean {registrable_domain(domain)!r}?)"
                )
                raise ValueError(msg)
        return value


class Phrase(BaseModel):
    """One pressure phrase and how much weight it carries."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    text: str = Field(min_length=2)
    weight: float = Field(gt=0.0, le=1.0)
    kind: str = Field(min_length=1)

    @field_validator("text")
    @classmethod
    def _lowercase(cls, value: str) -> str:
        return value.strip().lower()


class BrandBook(BaseModel):
    model_config = ConfigDict(extra="ignore")

    brands: tuple[Brand, ...] = Field(min_length=1)


class PhraseBook(BaseModel):
    model_config = ConfigDict(extra="ignore")

    phrases: tuple[Phrase, ...] = Field(min_length=1)


class AttachmentRisk(BaseModel):
    """Extensions and declared types that make an attachment worth reporting."""

    model_config = ConfigDict(extra="ignore", frozen=True)

    executable: frozenset[str] = Field(min_length=1)
    macro: frozenset[str] = Field(min_length=1)
    container: frozenset[str] = Field(min_length=1)
    expected_types: dict[str, tuple[str, ...]]
    double_extension_first: frozenset[str] = Field(min_length=1)


class UrlKnowledge(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True)

    shorteners: frozenset[str] = Field(min_length=1)
    open_redirect_hosts: frozenset[str]
    standard_ports: frozenset[int] = Field(min_length=1)
    max_subdomain_labels: int = Field(ge=2, le=10)


def _load(filename: str) -> dict[str, object]:
    path = DATA_DIR / filename
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as err:  # pragma: no cover - a packaging failure, not a data one
        msg = f"the phishing knowledge base is missing {filename}: {err}"
        raise RuntimeError(msg) from err
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError as err:
        msg = f"{filename} is not valid JSON: {err}"
        raise RuntimeError(msg) from err
    if not isinstance(decoded, dict):
        msg = f"{filename} must contain a JSON object, got {type(decoded).__name__}"
        raise RuntimeError(msg)
    return decoded


@lru_cache(maxsize=1)
def brands() -> tuple[Brand, ...]:
    """Every known brand. Validated on first access, then cached."""
    return BrandBook.model_validate(_load("brands.json")).brands


@lru_cache(maxsize=1)
def phrases() -> tuple[Phrase, ...]:
    """Pressure phrases, heaviest first so the first match found is the strongest."""
    book = PhraseBook.model_validate(_load("phrases.json")).phrases
    return tuple(sorted(book, key=lambda phrase: (-phrase.weight, phrase.text)))


@lru_cache(maxsize=1)
def attachment_risk() -> AttachmentRisk:
    return AttachmentRisk.model_validate(_load("attachments.json"))


@lru_cache(maxsize=1)
def url_knowledge() -> UrlKnowledge:
    return UrlKnowledge.model_validate(_load("urls.json"))


@lru_cache(maxsize=1)
def brand_domains() -> frozenset[str]:
    """Every legitimate brand domain, flattened.

    Used by the URL rules, which care whether a link host imitates *any* brand rather
    than which one.
    """
    return frozenset(domain for brand in brands() for domain in brand.domains)


@lru_cache(maxsize=1)
def _alias_index() -> tuple[tuple[str, Brand], ...]:
    """Aliases paired with their brand, longest first.

    Longest-first matters: "microsoft 365" must win over "microsoft", or the more
    specific claim is reported as the vaguer one.
    """
    pairs = [(alias, brand) for brand in brands() for alias in brand.aliases]
    return tuple(sorted(pairs, key=lambda pair: (-len(pair[0]), pair[0])))


def brand_claimed_in(text: str) -> Brand | None:
    """Which brand this text claims to be, if any.

    Substring matching on purpose: a display name is "PayPal Service" or
    "Microsoft 365 Security", not a bare brand token. The caller decides whether the
    claim is legitimate by checking the sending domain against ``brand.domains`` - and
    that second step is the whole difference between this and the previous
    implementation, which reported impersonation for any brand word found anywhere.
    """
    haystack = text.lower()
    for alias, brand in _alias_index():
        if alias in haystack:
            return brand
    return None


def brand_for_domain(domain: str) -> Brand | None:
    """The brand that legitimately owns ``domain``, if one does."""
    from app.agents.phishing.lookalike import registrable_domain

    registrable = registrable_domain(domain)
    for brand in brands():
        if registrable in brand.domains:
            return brand
    return None


def reset_cache() -> None:
    """Drop every cached table. For tests that vary the data files."""
    for cached in (
        brands,
        phrases,
        attachment_risk,
        url_knowledge,
        brand_domains,
        _alias_index,
    ):
        cached.cache_clear()
