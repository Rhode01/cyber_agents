"""Trivy JSON output parser.

Trivy (https://trivy.dev) produces JSON with a ``Results`` array.  Each result
covers one target (OS packages, language packages, or a container layer) and
contains a ``Vulnerabilities`` list.

Example::

    report = parse(raw_json)
    for target in report.targets:
        for vuln in target.vulnerabilities:
            print(target.target, vuln.vuln_id, vuln.severity, vuln.fixed_version)
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from app.parsers import ParseError


@dataclass
class TrivyVulnerability:
    vuln_id: str            # CVE-YYYY-NNNNN
    pkg_name: str
    installed_version: str
    fixed_version: str      # "" if no fix available
    severity: str           # CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN
    title: str
    description: str
    cvss_score: float       # 0.0 if not available
    references: list[str] = field(default_factory=list)


@dataclass
class TrivyTarget:
    target: str             # image name / file path
    target_type: str        # "container_image" / "filesystem" / language
    vulnerabilities: list[TrivyVulnerability] = field(default_factory=list)


@dataclass
class TrivyReport:
    schema_version: int
    artifact_name: str
    artifact_type: str
    targets: list[TrivyTarget] = field(default_factory=list)


def parse(raw: str) -> TrivyReport:
    """Parse Trivy JSON output.

    Raises ``ParseError`` on invalid JSON or unrecognised structure.
    """
    raw = raw.strip()
    if not raw:
        raise ParseError("Empty input")

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ParseError(f"Invalid JSON: {exc}") from exc

    schema_version = data.get("SchemaVersion", 0)
    artifact_name = data.get("ArtifactName", "")
    artifact_type = data.get("ArtifactType", "")

    targets: list[TrivyTarget] = []
    for result in data.get("Results", []):
        target_name = result.get("Target", "")
        target_type = result.get("Type", "")

        vulns: list[TrivyVulnerability] = []
        for v in result.get("Vulnerabilities") or []:
            # CVSS score — try NVD V3, then V2
            cvss_score = 0.0
            cvss = v.get("CVSS", {})
            for provider in ("nvd", "redhat", "ghsa"):
                if provider in cvss:
                    v3 = cvss[provider].get("V3Score") or cvss[provider].get("V2Score")
                    if v3 is not None:
                        try:
                            cvss_score = float(v3)
                        except (ValueError, TypeError):
                            pass
                        break

            vulns.append(TrivyVulnerability(
                vuln_id=v.get("VulnerabilityID", ""),
                pkg_name=v.get("PkgName", ""),
                installed_version=v.get("InstalledVersion", ""),
                fixed_version=v.get("FixedVersion", ""),
                severity=v.get("Severity", "UNKNOWN"),
                title=v.get("Title", ""),
                description=v.get("Description", ""),
                cvss_score=cvss_score,
                references=v.get("References", []),
            ))

        targets.append(
            TrivyTarget(target=target_name, target_type=target_type, vulnerabilities=vulns)
        )

    return TrivyReport(
        schema_version=schema_version,
        artifact_name=artifact_name,
        artifact_type=artifact_type,
        targets=targets,
    )
