"""Zeek log parser.

Parses Zeek TSV logs in the standard header format::

    #separator \\x09
    #fields ts uid id.orig_h ...
    1700000000.123456 Cn3QMo3Mkb1234 192.168.1.5 ...

Supports ``conn.log`` and ``dns.log`` — the two most relevant for the network
traffic analysis agent.

Example::

    records = parse_conn(raw_conn_log)
    dns_records = parse_dns(raw_dns_log)
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ZeekConnRecord:
    ts: float
    uid: str
    orig_h: str         # source IP
    orig_p: int         # source port
    resp_h: str         # destination IP
    resp_p: int         # destination port
    proto: str          # tcp / udp / icmp
    service: str        # http, dns, ssl …
    duration: float     # connection duration in seconds
    orig_bytes: int
    resp_bytes: int
    conn_state: str     # S0, SF, REJ, …
    missed_bytes: int
    orig_pkts: int
    resp_pkts: int


@dataclass
class ZeekDNSRecord:
    ts: float
    uid: str
    orig_h: str         # querying host
    orig_p: int
    resp_h: str         # DNS server
    resp_p: int
    proto: str
    query: str          # queried domain
    qtype_name: str     # A, AAAA, MX, PTR …
    rcode_name: str     # NOERROR, NXDOMAIN, SERVFAIL …
    answers: list[str] = field(default_factory=list)
    rejected: bool = False


# ---------------------------------------------------------------------------
# Shared header parsing
# ---------------------------------------------------------------------------

def _parse_header(lines: list[str]) -> tuple[str, list[str]]:
    """Extract separator and field names from Zeek log headers."""
    separator = "\t"
    fields: list[str] = []
    for line in lines:
        if line.startswith("#separator"):
            sep_raw = line.split(None, 1)[1].strip()
            separator = bytes(sep_raw, "utf-8").decode("unicode_escape")
        elif line.startswith("#fields"):
            fields = line.split(separator)[1:]
            fields = [f.strip() for f in fields]
    return separator, fields


def _parse_rows(raw: str, separator: str, fields: list[str]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        values = line.split(separator)
        row = {}
        for i, f in enumerate(fields):
            row[f] = values[i] if i < len(values) else "-"
        rows.append(row)
    return rows


def _safe_float(v: str) -> float:
    try:
        return float(v)
    except (ValueError, TypeError):
        return 0.0


def _safe_int(v: str) -> int:
    try:
        return int(v)
    except (ValueError, TypeError):
        return 0


# ---------------------------------------------------------------------------
# conn.log
# ---------------------------------------------------------------------------

def parse_conn(raw: str) -> list[ZeekConnRecord]:
    """Parse a Zeek conn.log."""
    lines = raw.splitlines()
    separator, fields = _parse_header(lines)
    if not fields:
        # Fallback: assume default tab-separated with standard conn.log field order
        fields = [
            "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
            "proto", "service", "duration", "orig_bytes", "resp_bytes",
            "conn_state", "local_orig", "local_resp", "missed_bytes",
            "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes",
        ]

    records: list[ZeekConnRecord] = []
    for row in _parse_rows(raw, separator, fields):
        records.append(ZeekConnRecord(
            ts=_safe_float(row.get("ts", "0")),
            uid=row.get("uid", ""),
            orig_h=row.get("id.orig_h", ""),
            orig_p=_safe_int(row.get("id.orig_p", "0")),
            resp_h=row.get("id.resp_h", ""),
            resp_p=_safe_int(row.get("id.resp_p", "0")),
            proto=row.get("proto", ""),
            service=row.get("service", "-"),
            duration=_safe_float(row.get("duration", "0")),
            orig_bytes=_safe_int(row.get("orig_bytes", "0")),
            resp_bytes=_safe_int(row.get("resp_bytes", "0")),
            conn_state=row.get("conn_state", ""),
            missed_bytes=_safe_int(row.get("missed_bytes", "0")),
            orig_pkts=_safe_int(row.get("orig_pkts", "0")),
            resp_pkts=_safe_int(row.get("resp_pkts", "0")),
        ))
    return records


# ---------------------------------------------------------------------------
# dns.log
# ---------------------------------------------------------------------------

def parse_dns(raw: str) -> list[ZeekDNSRecord]:
    """Parse a Zeek dns.log."""
    lines = raw.splitlines()
    separator, fields = _parse_header(lines)
    if not fields:
        fields = [
            "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
            "proto", "trans_id", "rtt", "query", "qclass", "qclass_name",
            "qtype", "qtype_name", "rcode", "rcode_name", "AA", "TC", "RD",
            "RA", "Z", "answers", "TTLs", "rejected",
        ]

    records: list[ZeekDNSRecord] = []
    for row in _parse_rows(raw, separator, fields):
        answers_raw = row.get("answers", "-")
        answers = (
            [a.strip() for a in answers_raw.split(",")]
            if answers_raw not in ("-", "")
            else []
        )
        rejected_raw = row.get("rejected", "F")
        rejected = rejected_raw.upper() in ("T", "TRUE", "1")

        records.append(ZeekDNSRecord(
            ts=_safe_float(row.get("ts", "0")),
            uid=row.get("uid", ""),
            orig_h=row.get("id.orig_h", ""),
            orig_p=_safe_int(row.get("id.orig_p", "0")),
            resp_h=row.get("id.resp_h", ""),
            resp_p=_safe_int(row.get("id.resp_p", "0")),
            proto=row.get("proto", "udp"),
            query=row.get("query", ""),
            qtype_name=row.get("qtype_name", ""),
            rcode_name=row.get("rcode_name", ""),
            answers=answers,
            rejected=rejected,
        ))
    return records
