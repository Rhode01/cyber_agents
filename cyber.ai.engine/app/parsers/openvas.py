"""OpenVAS / Greenbone XML report parser.

Parses the XML format produced by OpenVAS (GVM) and returns structured
vulnerability results grouped by host.

Example::

    report = parse(raw_xml)
    for result in report.results:
        print(result.host, result.nvt_name, result.severity, result.cve_ids)
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

from app.parsers import ParseError


@dataclass
class OpenVASResult:
    host: str
    port: str                   # e.g. "22/tcp"
    nvt_oid: str                # NVT OID
    nvt_name: str
    severity: float             # CVSS score (0.0-10.0)
    threat: str                 # High / Medium / Low / Log
    description: str
    solution: str
    cve_ids: list[str] = field(default_factory=list)
    xrefs: list[str] = field(default_factory=list)


@dataclass
class OpenVASReport:
    report_id: str
    target: str
    results: list[OpenVASResult] = field(default_factory=list)


def parse(raw: str) -> OpenVASReport:
    """Parse an OpenVAS/GVM XML report.

    Raises ``ParseError`` on invalid XML or unrecognised structure.
    """
    raw = raw.strip()
    if not raw:
        raise ParseError("Empty input")

    try:
        root = ET.fromstring(raw)  # noqa: S314
    except ET.ParseError as exc:
        raise ParseError(f"Invalid XML: {exc}") from exc

    # Handle both <report> at root and <get_reports_response><report>
    report_el = root if root.tag in ("report", "Report") else root.find(".//report")
    if report_el is None:
        raise ParseError("No <report> element found in OpenVAS XML")

    report_id = report_el.get("id", "")

    # Target host(s)
    host_el = report_el.find(".//target/hosts")
    target = host_el.text.strip() if host_el is not None and host_el.text else ""

    results: list[OpenVASResult] = []
    for res_el in report_el.findall(".//result"):
        host_text = ""
        host_node = res_el.find("host")
        if host_node is not None:
            host_text = (host_node.text or "").strip()

        port_el = res_el.find("port")
        port = port_el.text.strip() if port_el is not None and port_el.text else ""

        nvt_el = res_el.find("nvt")
        nvt_oid = nvt_el.get("oid", "") if nvt_el is not None else ""
        nvt_name_el = nvt_el.find("name") if nvt_el is not None else None
        nvt_name = nvt_name_el.text.strip() if nvt_name_el is not None and nvt_name_el.text else ""

        # CVE references
        cve_ids: list[str] = []
        if nvt_el is not None:
            for ref in nvt_el.findall(".//ref[@type='cve']"):
                cve_ids.append(ref.get("id", ""))
            for ref in nvt_el.findall(".//ref[@type='CVE']"):
                cve_ids.append(ref.get("id", ""))

        # Severity / CVSS
        severity_el = res_el.find("severity")
        severity_val = 0.0
        if severity_el is not None and severity_el.text:
            try:
                severity_val = float(severity_el.text.strip())
            except ValueError:
                pass

        threat_el = res_el.find("threat")
        threat = threat_el.text.strip() if threat_el is not None and threat_el.text else ""

        desc_el = res_el.find("description")
        description = desc_el.text.strip() if desc_el is not None and desc_el.text else ""

        sol_el = res_el.find(".//solution")
        solution = sol_el.text.strip() if sol_el is not None and sol_el.text else ""

        xrefs: list[str] = []
        for ref in res_el.findall(".//xref"):
            xrefs.append(ref.get("id", ref.text or ""))

        results.append(OpenVASResult(
            host=host_text,
            port=port,
            nvt_oid=nvt_oid,
            nvt_name=nvt_name,
            severity=severity_val,
            threat=threat,
            description=description,
            solution=solution,
            cve_ids=[c for c in cve_ids if c],
            xrefs=xrefs,
        ))

    return OpenVASReport(report_id=report_id, target=target, results=results)
