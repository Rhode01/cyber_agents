"""How old a domain is, over RDAP.

RDAP rather than WHOIS, for three reasons: it returns JSON instead of free text that varies
by registry, it is served over HTTPS on a documented endpoint, and it does not need a WHOIS
client library. The bootstrap service at ``rdap.org`` redirects to whichever registry is
authoritative for the TLD, so one URL covers every domain.

Age is one of the better single signals in phishing detection. Campaign infrastructure is
usually days old, because domains get reported and burned. It is not conclusive - a rebrand
or a campaign microsite is legitimately new - so the caller treats it as an indicator rather
than a verdict.

A failed lookup returns ``ok: False``, never an exception. Plenty of registries rate-limit
or answer oddly, and enrichment is allowed to learn nothing.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Final

import httpx

RDAP_BOOTSTRAP_URL: Final = "https://rdap.org/domain"
TIMEOUT_SECONDS: Final = 8.0
MAX_RESPONSE_BYTES: Final = 256_000

# Event names that mean "the domain came into existence". Registries are inconsistent about
# which they use, so all three are accepted and the earliest wins.
_CREATION_EVENTS: Final[frozenset[str]] = frozenset(
    {"registration", "created", "last changed registration"}
)


def _failure(domain: str, reason: str) -> dict[str, Any]:
    return {
        "ok": False,
        "tool": "lookup_domain_age",
        "domain": domain,
        "error": reason,
        "age_days": None,
        "registered": None,
    }


def _parse_timestamp(raw: str) -> datetime | None:
    """Parse an RDAP timestamp, tolerating the variants registries emit."""
    candidate = raw.strip()
    if not candidate:
        return None
    # RDAP specifies RFC 3339, but 'Z' is common and fromisoformat only learned it in 3.11.
    candidate = candidate.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    # A naive timestamp is assumed UTC: registries that omit the offset publish UTC, and
    # guessing local time would shift the age by hours for no reason.
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed


def _earliest_registration(payload: dict[str, Any]) -> datetime | None:
    events = payload.get("events")
    if not isinstance(events, list):
        return None

    found: list[datetime] = []
    for event in events:
        if not isinstance(event, dict):
            continue
        action = str(event.get("eventAction", "")).strip().lower()
        if action not in _CREATION_EVENTS:
            continue
        stamp = _parse_timestamp(str(event.get("eventDate", "")))
        if stamp is not None:
            found.append(stamp)
    return min(found) if found else None


async def lookup_domain_age(domain: str) -> dict[str, Any]:
    """Return how many days ago ``domain`` was registered.

    Args:
        domain: A registrable domain, e.g. ``paypal.com``.

    Returns:
        A result dict with ``age_days`` and the ISO ``registered`` timestamp. ``ok`` is
        False when the registry could not be reached or published no registration event -
        some ccTLDs deliberately do not.
    """
    cleaned = (domain or "").strip().strip(".").lower()
    if not cleaned:
        return _failure(domain, "No domain was supplied.")

    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(TIMEOUT_SECONDS),
            # The bootstrap endpoint redirects to the authoritative registry, so redirects
            # must be followed. Safe here in a way it is not in `fetch.py`: the host is
            # ours to trust, not one an attacker chose.
            follow_redirects=True,
            headers={"accept": "application/rdap+json, application/json"},
            trust_env=False,
        ) as client:
            response = await client.get(f"{RDAP_BOOTSTRAP_URL}/{cleaned}")
    except httpx.HTTPError as err:
        return _failure(cleaned, f"The RDAP lookup failed: {type(err).__name__}: {err}")

    if response.status_code == 404:
        # Meaningful rather than an error: no registry has a record of it.
        return _failure(cleaned, "No registry has a record for this domain.")
    if response.status_code != 200:
        return _failure(cleaned, f"The registry answered {response.status_code}.")
    if len(response.content) > MAX_RESPONSE_BYTES:
        return _failure(cleaned, "The registry's response was implausibly large.")

    try:
        payload = response.json()
    except ValueError:
        return _failure(cleaned, "The registry's response was not JSON.")
    if not isinstance(payload, dict):
        return _failure(cleaned, "The registry's response was not an RDAP object.")

    registered = _earliest_registration(payload)
    if registered is None:
        return _failure(cleaned, "The registry published no registration date.")

    age_days = (datetime.now(UTC) - registered).days
    return {
        "ok": True,
        "tool": "lookup_domain_age",
        "domain": cleaned,
        "error": "",
        "age_days": age_days,
        "registered": registered.isoformat(),
        "registrar": _registrar_of(payload),
    }


def _registrar_of(payload: dict[str, Any]) -> str:
    """The registrar's name, when the response carries one.

    Buried in RDAP's vCard array format, which is a list of ``["fn", {}, "text", value]``
    entries. Best-effort: a missing registrar is not worth failing the whole lookup.
    """
    entities = payload.get("entities")
    if not isinstance(entities, list):
        return ""
    for entity in entities:
        if not isinstance(entity, dict):
            continue
        roles = entity.get("roles")
        if not (isinstance(roles, list) and "registrar" in roles):
            continue
        vcard = entity.get("vcardArray")
        if not (isinstance(vcard, list) and len(vcard) > 1 and isinstance(vcard[1], list)):
            continue
        for field in vcard[1]:
            if isinstance(field, list) and len(field) >= 4 and field[0] == "fn":
                return str(field[3])[:200]
    return ""
