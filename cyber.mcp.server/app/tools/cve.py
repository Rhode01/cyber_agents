"""CVE enrichment.

**Enrichment only.** This never creates a finding. The rule engine in the
ai.engine decides that a CVE applies, from a version range it can defend; what
comes back from here adds a CVSS score, a summary and an exploit signal to a
finding that already exists. Keeping that split means an outage of this API, or a
wrong answer from it, cannot invent a vulnerability.

Every failure mode - unreachable, rate-limited, malformed, unknown id - returns a
result with a ``status`` the caller can read, never an exception. An agent that
cannot look up a CVE should carry on with a lower-confidence finding, not abort
the assessment.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass
from typing import Any, Final

import httpx

logger = logging.getLogger("app")

CVE_ID_RE: Final = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)

# Bounded so a long-running server cannot grow this without limit; CVE records
# change rarely enough that an hour-old answer is still a good answer.
_MAX_CACHE_ENTRIES: Final = 512


@dataclass(slots=True)
class _CacheEntry:
    payload: dict[str, Any]
    expires_at: float


class CveLookup:
    """A TTL-cached CVE lookup over one shared HTTP client."""

    def __init__(
        self,
        client: httpx.AsyncClient,
        *,
        base_url: str,
        timeout_seconds: float,
        ttl_seconds: float,
    ) -> None:
        self._client = client
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout_seconds
        self._ttl = ttl_seconds
        self._cache: dict[str, _CacheEntry] = {}

    def _cached(self, cve_id: str) -> dict[str, Any] | None:
        entry = self._cache.get(cve_id)
        if entry is None:
            return None
        if entry.expires_at < time.monotonic():
            del self._cache[cve_id]
            return None
        return entry.payload

    def _store(self, cve_id: str, payload: dict[str, Any]) -> None:
        if self._ttl <= 0:
            return
        if len(self._cache) >= _MAX_CACHE_ENTRIES:
            # Evict the entry closest to expiry rather than an arbitrary one.
            oldest = min(self._cache, key=lambda key: self._cache[key].expires_at)
            del self._cache[oldest]
        self._cache[cve_id] = _CacheEntry(payload, time.monotonic() + self._ttl)

    async def lookup(self, cve_id: str) -> dict[str, Any]:
        """Fetch one CVE record. Always returns a dict with a ``status``."""
        normalized = cve_id.strip().upper()
        if not CVE_ID_RE.match(normalized):
            return {
                "cve_id": cve_id,
                "status": "invalid",
                "detail": "Not a CVE identifier. Expected the form CVE-2021-44228.",
            }

        hit = self._cached(normalized)
        if hit is not None:
            return {**hit, "cached": True}

        try:
            response = await self._client.get(
                f"{self._base_url}/{normalized}", timeout=self._timeout
            )
        except httpx.HTTPError as exc:
            logger.warning("cve.lookup.unreachable cve=%s error=%s", normalized, exc)
            return {
                "cve_id": normalized,
                "status": "unavailable",
                "detail": f"The CVE service could not be reached: {exc}",
            }

        if response.status_code == 404:
            payload = {"cve_id": normalized, "status": "not-found"}
            self._store(normalized, payload)
            return payload

        if response.is_error:
            logger.warning("cve.lookup.error cve=%s status=%s", normalized, response.status_code)
            return {
                "cve_id": normalized,
                "status": "unavailable",
                "detail": f"The CVE service answered {response.status_code}.",
            }

        try:
            body = response.json()
        except ValueError:
            return {
                "cve_id": normalized,
                "status": "unavailable",
                "detail": "The CVE service returned a body that is not JSON.",
            }

        if not isinstance(body, dict) or not body:
            payload = {"cve_id": normalized, "status": "not-found"}
            self._store(normalized, payload)
            return payload

        payload = _summarize(normalized, body)
        self._store(normalized, payload)
        return payload


def _first_number(*values: object) -> float | None:
    """The first value that is usable as a CVSS score."""
    for value in values:
        if isinstance(value, int | float) and 0 < float(value) <= 10:
            return round(float(value), 1)
        if isinstance(value, str):
            try:
                parsed = float(value)
            except ValueError:
                continue
            if 0 < parsed <= 10:
                return round(parsed, 1)
    return None


def _summarize(cve_id: str, body: dict[str, Any]) -> dict[str, Any]:
    """Reduce a provider record to the handful of fields prioritisation uses.

    Field names differ between and within CVE providers, so each is looked up in
    a few likely places and simply omitted when absent. A missing score is not an
    error; it means the exploit factor stays "unknown", which scores lower than a
    known exploit and higher than a known-absent one.
    """
    containers = body.get("containers")
    cna = containers.get("cna", {}) if isinstance(containers, dict) else {}

    summary = (
        body.get("summary")
        or body.get("description")
        or _cve5_description(cna)
        or ""
    )

    cvss_data = body.get("cvss_data")
    cvss = _first_number(
        body.get("cvss3"),
        body.get("cvss"),
        cvss_data.get("score") if isinstance(cvss_data, dict) else None,
        _cve5_cvss(cna),
    )

    references = body.get("references") or _cve5_references(cna)
    if not isinstance(references, list):
        references = []

    known_exploited = bool(
        body.get("known_exploited") or body.get("kev") or body.get("cisa_kev")
    )

    return {
        "cve_id": cve_id,
        "status": "ok",
        "summary": str(summary)[:2000],
        "cvss": cvss,
        "published": str(body.get("published") or body.get("Published") or "") or None,
        "modified": str(body.get("modified") or body.get("Modified") or "") or None,
        "known_exploited": known_exploited,
        "references": [str(ref) for ref in references[:5]],
        "cached": False,
        "note": "Enrichment from an external CVE service. Not used to create findings.",
    }


def _cve5_description(cna: dict[str, Any]) -> str:
    descriptions = cna.get("descriptions")
    if isinstance(descriptions, list):
        for entry in descriptions:
            if isinstance(entry, dict) and entry.get("value"):
                return str(entry["value"])
    return ""


def _cve5_cvss(cna: dict[str, Any]) -> float | None:
    metrics = cna.get("metrics")
    if not isinstance(metrics, list):
        return None
    for metric in metrics:
        if not isinstance(metric, dict):
            continue
        for key, value in metric.items():
            if key.startswith("cvssV") and isinstance(value, dict):
                score = _first_number(value.get("baseScore"))
                if score is not None:
                    return score
    return None


def _cve5_references(cna: dict[str, Any]) -> list[str]:
    references = cna.get("references")
    if not isinstance(references, list):
        return []
    return [str(ref["url"]) for ref in references if isinstance(ref, dict) and ref.get("url")]
