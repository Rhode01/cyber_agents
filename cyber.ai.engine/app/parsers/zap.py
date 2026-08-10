"""OWASP ZAP report parser.

Supports ZAP's JSON report format (from ``-J`` flag or the REST API).

Each alert contains a risk level, confidence, OWASP category, and a list of
affected URLs with evidence.

Example::

    report = parse(raw_json)
    for alert in report.alerts:
        print(alert.risk, alert.name, alert.owasp_id, len(alert.instances))
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any

from app.parsers import ParseError


@dataclass
class ZAPInstance:
    uri: str
    method: str
    param: str
    attack: str
    evidence: str


@dataclass
class ZAPAlert:
    plugin_id: str
    name: str
    risk: str           # High / Medium / Low / Informational
    confidence: str     # High / Medium / Low / False Positive
    description: str
    solution: str
    reference: str
    owasp_id: str       # A01:2025 etc., extracted from tags/references
    cwe_id: str
    wasc_id: str
    instances: list[ZAPInstance] = field(default_factory=list)


@dataclass
class ZAPReport:
    site: str
    alerts: list[ZAPAlert] = field(default_factory=list)


# OWASP Top 10:2025 mapping keywords -> ID
_OWASP_PATTERN = re.compile(r"A(\d{2})(?::\d{4})?", re.IGNORECASE)


def _extract_owasp_id(tags: list[dict[str, Any]], reference: str) -> str:
    """Try to find an OWASP Top 10 ID from tags or reference text."""
    for tag in tags:
        tag_name = tag.get("tag", "")
        m = _OWASP_PATTERN.search(tag_name)
        if m:
            return f"A{m.group(1)}"
    m = _OWASP_PATTERN.search(reference)
    if m:
        return f"A{m.group(1)}"
    return ""


def parse(raw: str) -> ZAPReport:
    """Parse a ZAP JSON report.

    Falls back to XML if JSON parsing fails.
    Raises ``ParseError`` if neither format is recognised.
    """
    raw = raw.strip()
    if not raw:
        raise ParseError("Empty input")

    if raw.startswith("{") or raw.startswith("["):
        return _parse_json(raw)

    if raw.startswith("<") or "<?xml" in raw[:20]:
        return _parse_xml(raw)

    raise ParseError("ZAP report must be JSON or XML")


def _parse_json(raw: str) -> ZAPReport:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ParseError(f"Invalid JSON: {exc}") from exc

    # ZAP JSON report wraps everything under a "site" key
    site_list = data if isinstance(data, list) else data.get("site", [data])
    if isinstance(site_list, dict):
        site_list = [site_list]

    all_alerts: list[ZAPAlert] = []
    site_name = ""

    for site_data in site_list:
        if isinstance(site_data, dict):
            site_name = str(site_data.get("@name") or site_data.get("name") or "")
            alerts_raw = site_data.get("alerts", site_data.get("alertitem", [])) or []
        else:
            alerts_raw = []

        for a in alerts_raw:
            instances: list[ZAPInstance] = []
            for inst in a.get("instances", a.get("instance", [])) or []:
                if isinstance(inst, dict):
                    instances.append(ZAPInstance(
                        uri=str(inst.get("uri") or inst.get("url") or ""),
                        method=str(inst.get("method") or "GET"),
                        param=str(inst.get("param") or ""),
                        attack=str(inst.get("attack") or ""),
                        evidence=str(inst.get("evidence") or ""),
                    ))

            tags = a.get("tags", {})
            if isinstance(tags, dict):
                tags = [{"tag": k} for k in tags]
            reference = a.get("reference", "")
            owasp_id = _extract_owasp_id(tags if isinstance(tags, list) else [], reference)

            all_alerts.append(ZAPAlert(
                plugin_id=str(a.get("pluginid", a.get("id", ""))),
                name=a.get("name", a.get("alert", "")),
                risk=a.get("riskdesc", a.get("risk", "")).split(" ")[0],
                confidence=a.get("confidence", a.get("confidencedesc", "")).split(" ")[0],
                description=a.get("desc", a.get("description", "")),
                solution=a.get("solution", ""),
                reference=reference,
                owasp_id=owasp_id,
                cwe_id=str(a.get("cweid", "")),
                wasc_id=str(a.get("wascid", "")),
                instances=instances,
            ))

    return ZAPReport(site=site_name, alerts=all_alerts)


def _parse_xml(raw: str) -> ZAPReport:
    try:
        root = ET.fromstring(raw)  # noqa: S314
    except ET.ParseError as exc:
        raise ParseError(f"Invalid XML: {exc}") from exc

    site_el = root.find("site") or root
    site_name = site_el.get("name", "")

    alerts: list[ZAPAlert] = []
    for alert_el in site_el.findall(".//alertitem") + site_el.findall(".//alert"):
        def _text(tag: str, el: ET.Element = alert_el) -> str:
            found = el.find(tag)
            return found.text.strip() if found is not None and found.text else ""

        instances: list[ZAPInstance] = []
        for inst_el in alert_el.findall(".//instance"):
            instances.append(ZAPInstance(
                uri=_text_from(inst_el, "uri") or _text_from(inst_el, "url"),
                method=_text_from(inst_el, "method"),
                param=_text_from(inst_el, "param"),
                attack=_text_from(inst_el, "attack"),
                evidence=_text_from(inst_el, "evidence"),
            ))

        reference = _text("reference")
        owasp_id = _extract_owasp_id([], reference)

        alerts.append(ZAPAlert(
            plugin_id=_text("pluginid"),
            name=_text("name") or _text("alert"),
            risk=_text("riskdesc").split(" ")[0] or _text("risk"),
            confidence=_text("confidence"),
            description=_text("desc") or _text("description"),
            solution=_text("solution"),
            reference=reference,
            owasp_id=owasp_id,
            cwe_id=_text("cweid"),
            wasc_id=_text("wascid"),
            instances=instances,
        ))

    return ZAPReport(site=site_name, alerts=alerts)


def _text_from(el: ET.Element, tag: str) -> str:
    child = el.find(tag)
    return child.text.strip() if child is not None and child.text else ""
