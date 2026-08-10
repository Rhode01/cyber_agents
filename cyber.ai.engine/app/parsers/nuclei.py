"""Nuclei JSON output parser.

Nuclei (https://nuclei.projectdiscovery.io) produces one JSON object per line
(NDJSON) when run with ``-json``.

Example::

    findings = parse(raw_json)
    for f in findings:
        print(f.template_id, f.severity, f.matched_at)
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any


@dataclass
class NucleiFinding:
    template_id: str
    template_name: str
    severity: str           # critical / high / medium / low / info / unknown
    matched_at: str         # URL or host that was matched
    host: str
    matched_line: str       # matched HTTP response line or pattern
    description: str
    tags: list[str] = field(default_factory=list)
    reference: list[str] = field(default_factory=list)
    curl_command: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


def parse(raw: str) -> list[NucleiFinding]:
    """Parse Nuclei NDJSON output.

    Silently skips malformed lines.
    Returns an empty list if no findings are present.
    """
    findings: list[NucleiFinding] = []

    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue

        # Nuclei output structure (v2/v3 compatible)
        info = record.get("info", {})
        matched_at = record.get("matched-at", record.get("matched", ""))

        # Severity may be nested under info or at top level
        severity = (
            info.get("severity", record.get("severity", "unknown"))
            .lower()
            .strip()
        )

        description = info.get("description", record.get("description", ""))
        tags = info.get("tags", [])
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",")]

        references = info.get("reference", info.get("references", []))
        if isinstance(references, str):
            references = [references]

        findings.append(NucleiFinding(
            template_id=record.get("template-id", record.get("templateID", "")),
            template_name=info.get("name", record.get("template-id", "")),
            severity=severity,
            matched_at=matched_at,
            host=record.get("host", ""),
            matched_line=record.get("matched-line", ""),
            description=description,
            tags=tags,
            reference=references,
            curl_command=record.get("curl-command", ""),
            extra={k: v for k, v in record.items() if k not in (
                "template-id", "templateID", "info", "matched-at", "matched",
                "host", "matched-line", "description", "curl-command",
            )},
        ))

    return findings
