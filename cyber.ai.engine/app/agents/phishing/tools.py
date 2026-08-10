"""Tools for the phishing detection agent. Declared, not yet bound to the model."""

from __future__ import annotations

import json
import re
import time
from typing import Any

from langchain_core.tools import tool

from ai_engine.agents.common.scanning import duration_seconds, run_command

_PHISHING_TIMEOUT_SECONDS = 45.0
_MAX_LINKS = 20
_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)


@tool
def check_email_authentication(message_id: str) -> dict[str, Any]:
    """Return SPF, DKIM, and DMARC results and alignment for a stored message."""
    # TODO(phase-2): resolve through the backend, which stores ingested messages.
    return {"message_id": message_id, "status": "not-implemented", "source": "phase-1-stub"}


@tool
def check_domain_reputation(domain: str) -> dict[str, Any]:
    """Return registration age, reputation score, and lookalike matches for a domain."""
    # TODO(phase-2): resolve through the backend's threat-intel integration.
    return {"domain": domain, "status": "not-implemented", "source": "phase-1-stub"}


TOOLS = [check_email_authentication, check_domain_reputation]


# ---------------------------------------------------------------------------
# Self-launched analysis (MVP)
# ---------------------------------------------------------------------------

def _extract_domain(target: str) -> str:
    """Pull the registrable-looking domain out of a URL, domain, or email."""
    cleaned = (target or "").strip().rstrip("/")
    if not cleaned:
        return ""

    if "@" in cleaned and cleaned.rsplit("@", 1)[1]:
        return cleaned.rsplit("@", 1)[1].split("?")[0].lower()

    if "://" in cleaned:
        cleaned = cleaned.split("://", 1)[1]
    cleaned = cleaned.split("/")[0].split("?")[0].split("#")[0]
    # Strip an explicit port (IPv6 literals are out of MVP scope).
    if cleaned.count(":") == 1 and not cleaned.startswith("["):
        cleaned = cleaned.split(":", 1)[0]
    return cleaned.lower()


async def _dig_txt_records(domain: str, prefix: str) -> list[str]:
    """Return the quoted TXT records for ``prefix.domain`` (or ``domain``)."""
    fqdn = f"{prefix}.{domain}" if prefix else domain
    returncode, stdout, _stderr = await run_command(
        ["dig", "+short", "TXT", fqdn],
        timeout_seconds=15,
        label="dig",
    )
    if returncode != 0 or not stdout.strip():
        return []

    records: list[str] = []
    for line in stdout.splitlines():
        record = line.strip().strip('"')
        # Multi-chunk quoted strings become one line in +short output.
        if record and record not in records:
            records.append(record)
    return records


def _auth_result(records: list[str], marker: str) -> str:
    """Map DNS auth records to pass/none/error semantics used by rule_check."""
    if any(record.lower().startswith(marker) for record in records):
        return "pass"
    if records:
        return "none"
    return "none"


async def _fetch_url_report(url: str) -> dict[str, Any]:
    """Follow a URL with curl and return derived phishing features."""
    meta: dict[str, Any] = {
        "target_type": "url",
        "http_status": None,
        "final_url": url,
        "num_redirects": 0,
    }

    marker = "__CURL_META__"
    returncode, stdout, stderr = await run_command(
        [
            "curl", "-s", "-L", "-m", "20", "-A", _USER_AGENT,
            "-w", f"\n{marker} %{{http_code}} %{{url_effective}} %{{num_redirects}}",
            "-o", "-", url,
        ],
        timeout_seconds=30,
        label="curl",
    )
    if returncode != 0:
        meta["error"] = stderr.strip() or f"curl exited with {returncode}"
        return meta

    if marker in stdout:
        body, _, tail = stdout.rpartition(marker)
        fields = tail.split()
        if len(fields) >= 3:
            meta["http_status"] = fields[0]
            meta["final_url"] = fields[1]
            meta["num_redirects"] = int(fields[2] or 0)
    else:
        body = stdout

    title = ""
    title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
    if title_match:
        title = re.sub(r"<[^>]+>", "", title_match.group(1)).strip()[:200]

    links: list[str] = re.findall(
        r"""href\s*=\s*["'](http[s]?://[^"']+)""", body, re.IGNORECASE
    )[:_MAX_LINKS]
    link_domains = list(dict.fromkeys(_extract_domain(link) for link in links))

    meta.update({
        "title": title,
        "links": links,
        "link_domains": [d for d in link_domains if d],
        "content_snippet": re.sub(r"<[^>]+>", " ", body)[:500].strip(),
    })
    return meta


async def analyze_url_or_domain(target: str) -> dict[str, Any]:
    """Run live DNS auth and (for URLs) HTTP checks against ``target``.

    Returns a JSON report whose keys mirror the fields the phishing agent's
    rule engine consumes (``spf_result``, ``dkim_result``, ``dmarc_result``,
    ``link_domains``, ...), so a URL/domain artifact flows through the same
    ``normalize -> rule_check -> reason -> emit_findings`` path as a raw email.
    """
    target = (target or "").strip()
    if not target:
        return {"ok": False, "tool": "url-scan", "output": "", "error": "Empty target", "meta": {}}

    started_at = time.monotonic()
    domain = _extract_domain(target)
    report: dict[str, Any] = {
        "subject": "",
        "sender": target,
        "sender_domain": domain,
        "display_name": "",
        "reply_to": "",
        "reply_to_domain": "",
        "spf_result": "none",
        "dkim_result": "none",
        "dmarc_result": "none",
        "links": [],
        "link_domains": [],
        "urgency_phrases": [],
        "brand_keywords": [],
        "meta": {"target_type": "domain", "dns_notes": []},
    }

    if not domain:
        return {
            "ok": False,
            "tool": "url-scan",
            "output": json.dumps(report, indent=2),
            "error": f"Could not extract a domain from '{target}'",
            "meta": {},
        }

    spf_records = await _dig_txt_records(domain, "")
    dmarc_records = await _dig_txt_records(domain, "_dmarc")
    dkim_records = await _dig_txt_records(domain, "default._domainkey")

    if not spf_records and not dmarc_records and not dkim_records:
        report["meta"]["dns_notes"].append("no SPF/DMARC/DKIM TXT records found")
    report["spf_result"] = _auth_result(spf_records, "v=spf1")
    report["dmarc_result"] = _auth_result(dmarc_records, "v=dmarc1")
    report["dkim_result"] = "pass" if dkim_records else "none"

    if target.lower().startswith(("http://", "https://")):
        url_report = await _fetch_url_report(target)
        report["meta"].update(url_report)
        report["subject"] = url_report.get("title", "")
        report["links"] = url_report.get("links", [])
        report["link_domains"] = url_report.get("link_domains", [])
        report["meta"]["target_type"] = "url"

    output = json.dumps(report, indent=2)
    return {
        "ok": True,
        "tool": "url-scan",
        "output": output,
        "error": None,
        "meta": {
            "duration_seconds": duration_seconds(started_at),
            "target": target,
            "domain": domain,
            "record_count": len(spf_records) + len(dmarc_records) + len(dkim_records),
        },
    }
