"""Nmap parser tests.

The parser is the platform's boundary against a hostile file upload, so these
tests are as much about what it *refuses* as what it extracts.

The most important assertion here is the one that looks wrong at first glance:
injected content must survive **byte for byte**. Sanitising at parse time would
destroy the evidence the injection detector needs and would imply a safety that
does not exist - fencing happens once, later, at the prompt boundary.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from cyber_contracts import ScanFormat

from app.services.ingestion import ScanParseError, detect_format, parse, parse_nmap_xml
from app.services.ingestion.errors import UnsupportedScanFormatError
from app.services.ingestion.nmap import MAX_HOSTS, MAX_PORTS_PER_HOST

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


# --------------------------------------------------------------- extraction --


def test_parses_hosts_ports_and_services() -> None:
    scan = parse_nmap_xml(fixture("nmap-basic.xml"))

    assert scan.format is ScanFormat.nmap_xml
    assert scan.scanner == "nmap"
    assert scan.scanner_version == "7.94"
    assert scan.started_at is not None
    assert scan.started_at.tzinfo is not None

    # Three hosts: two up, one down. The down host survives with no ports.
    assert [h.address for h in scan.hosts] == ["10.0.0.5", "10.0.0.6", "10.0.0.7"]
    assert scan.host_count == 3

    by_address = {h.address: h for h in scan.hosts}
    assert by_address["10.0.0.7"].status == "down"
    assert by_address["10.0.0.7"].ports == []


def test_closed_ports_are_dropped() -> None:
    """8080 is `closed` in the fixture and must not reach the agents."""
    scan = parse_nmap_xml(fixture("nmap-basic.xml"))
    host = next(h for h in scan.hosts if h.address == "10.0.0.5")

    assert sorted(p.port for p in host.ports) == [22, 23, 80]
    assert all(p.state == "open" for p in host.ports)
    assert scan.open_port_count == 5


def test_service_fields_and_cpe_are_extracted() -> None:
    scan = parse_nmap_xml(fixture("nmap-basic.xml"))
    host = next(h for h in scan.hosts if h.address == "10.0.0.5")
    ssh = next(p for p in host.ports if p.port == 22)

    assert ssh.protocol == "tcp"
    assert ssh.service == "ssh"
    assert ssh.product == "OpenSSH"
    assert ssh.version == "7.4p1 Debian 10+deb9u7"
    assert ssh.extrainfo == "protocol 2.0"
    assert ssh.cpe == ["cpe:/a:openbsd:openssh:7.4p1"]


def test_a_service_with_no_version_still_parses() -> None:
    """Telnet in the fixture has a name and nothing else."""
    scan = parse_nmap_xml(fixture("nmap-basic.xml"))
    host = next(h for h in scan.hosts if h.address == "10.0.0.5")
    telnet = next(p for p in host.ports if p.port == 23)

    assert telnet.service == "telnet"
    assert telnet.product is None
    assert telnet.version is None
    assert telnet.cpe == []


def test_multiple_hostnames_are_kept_and_deduplicated() -> None:
    scan = parse_nmap_xml(fixture("nmap-basic.xml"))
    host = next(h for h in scan.hosts if h.address == "10.0.0.6")

    assert host.hostnames == ["cache-01.corp.internal", "redis.corp.internal"]


# ------------------------------------------------------------- untrusted in --


def test_injected_content_survives_byte_for_byte() -> None:
    """The parser must not sanitise. See this module's docstring."""
    scan = parse_nmap_xml(fixture("nmap-injection.xml"))
    host = scan.hosts[0]
    ssh = next(p for p in host.ports if p.port == 22)

    assert ssh.product is not None
    assert "IGNORE ALL PREVIOUS INSTRUCTIONS" in ssh.product

    # An attempt to close the untrusted fence early is carried through as data.
    # Neutralising it is wrap_untrusted's job, not the parser's.
    assert ssh.extrainfo is not None
    assert "UNTRUSTED_VULNERABILITY_SCAN_CANDIDATES_END" in ssh.extrainfo

    # A homoglyph hostname (Cyrillic U+0430) is preserved, not normalised away.
    assert "а" in host.hostnames[0]

    # A bidi override (U+202E) planted in a banner also survives.
    ftp = next(p for p in host.ports if p.port == 21)
    assert ftp.extrainfo is not None
    assert "‮" in ftp.extrainfo


def test_a_fabricated_cve_in_a_banner_stays_in_the_banner() -> None:
    """The parser never promotes banner text into a structured CVE field.

    Only the rule engine may produce cve_ids, so a CVE id invented by a scanned
    host must remain inert banner content.
    """
    scan = parse_nmap_xml(fixture("nmap-injection.xml"))
    ftp = next(p for p in scan.hosts[0].ports if p.port == 21)

    assert ftp.extrainfo is not None
    assert "CVE-9999-00001" in ftp.extrainfo
    # ScanPort has no CVE field at all - there is nowhere for it to leak to.
    assert not hasattr(ftp, "cve_ids")


# ------------------------------------------------------------------ refusals --


def test_entity_expansion_is_refused() -> None:
    """A billion-laughs payload must raise, not exhaust memory."""
    with pytest.raises(ScanParseError) as err:
        parse_nmap_xml(fixture("nmap-billion-laughs.xml"))

    assert "unsafe to parse" in str(err.value)


def test_malformed_xml_is_refused() -> None:
    with pytest.raises(ScanParseError) as err:
        parse_nmap_xml(fixture("nmap-malformed.xml"))

    assert "not well-formed" in str(err.value)


def test_a_non_nmap_document_is_refused() -> None:
    with pytest.raises(ScanParseError) as err:
        parse_nmap_xml("<report><foo/></report>")

    assert "nmaprun" in str(err.value)


def test_empty_input_is_refused() -> None:
    for content in ("", "   ", "\n\t "):
        with pytest.raises(ScanParseError):
            parse_nmap_xml(content)


# -------------------------------------------------------------------- bounds --


def test_too_many_hosts_is_refused_rather_than_truncated() -> None:
    """Exceeding a bound must fail loudly: a silently truncated host list would
    read as "the rest of the network is clean"."""
    hosts = "".join(
        f'<host><status state="up"/><address addr="10.0.{i // 256}.{i % 256}" addrtype="ipv4"/></host>'
        for i in range(MAX_HOSTS + 1)
    )
    with pytest.raises(ScanParseError) as err:
        parse_nmap_xml(f'<nmaprun scanner="nmap" version="7.94">{hosts}</nmaprun>')

    assert "above the" in str(err.value)


def test_too_many_ports_on_one_host_is_refused() -> None:
    ports = "".join(
        f'<port protocol="tcp" portid="{i + 1}"><state state="open"/></port>'
        for i in range(MAX_PORTS_PER_HOST + 1)
    )
    xml = (
        '<nmaprun scanner="nmap" version="7.94"><host><status state="up"/>'
        '<address addr="10.0.0.5" addrtype="ipv4"/>'
        f"<ports>{ports}</ports></host></nmaprun>"
    )
    with pytest.raises(ScanParseError) as err:
        parse_nmap_xml(xml)

    assert "ports" in str(err.value)


def test_an_overlong_banner_is_clipped_to_the_contract_length() -> None:
    """A 10 KB product string must not fail contract validation."""
    xml = (
        '<nmaprun scanner="nmap" version="7.94"><host><status state="up"/>'
        '<address addr="10.0.0.5" addrtype="ipv4"/><ports>'
        '<port protocol="tcp" portid="22"><state state="open"/>'
        f'<service name="ssh" product="{"A" * 10_000}"/>'
        "</port></ports></host></nmaprun>"
    )
    scan = parse_nmap_xml(xml)
    product = scan.hosts[0].ports[0].product

    assert product is not None
    assert len(product) == 256


def test_a_host_with_no_usable_address_is_skipped() -> None:
    xml = (
        '<nmaprun scanner="nmap" version="7.94">'
        '<host><status state="up"/><address addr="AA:BB:CC:DD:EE:FF" addrtype="mac"/></host>'
        '<host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/></host>'
        "</nmaprun>"
    )
    scan = parse_nmap_xml(xml)

    assert [h.address for h in scan.hosts] == ["10.0.0.5"]


def test_a_junk_port_number_is_skipped_not_fatal() -> None:
    xml = (
        '<nmaprun scanner="nmap" version="7.94"><host><status state="up"/>'
        '<address addr="10.0.0.5" addrtype="ipv4"/><ports>'
        '<port protocol="tcp" portid="not-a-number"><state state="open"/></port>'
        '<port protocol="tcp" portid="99999"><state state="open"/></port>'
        '<port protocol="tcp" portid="22"><state state="open"/></port>'
        "</ports></host></nmaprun>"
    )
    scan = parse_nmap_xml(xml)

    assert [p.port for p in scan.hosts[0].ports] == [22]


def test_a_junk_start_timestamp_becomes_none() -> None:
    xml = '<nmaprun scanner="nmap" version="7.94" start="not-a-timestamp"></nmaprun>'

    assert parse_nmap_xml(xml).started_at is None


# --------------------------------------------------------- format detection --


def test_detect_format_recognises_nmap_and_openvas() -> None:
    assert detect_format(fixture("nmap-basic.xml")) is ScanFormat.nmap_xml
    assert detect_format(fixture("nmap-injection.xml")) is ScanFormat.nmap_xml
    assert detect_format("<get_reports_response><report/></get_reports_response>") is (
        ScanFormat.openvas_xml
    )


def test_detect_format_refuses_something_unrecognisable() -> None:
    with pytest.raises(ScanParseError) as err:
        detect_format('{"findings": []}')

    assert "could not identify" in str(err.value)


def test_parse_dispatches_by_format() -> None:
    scan = parse(fixture("nmap-basic.xml"), ScanFormat.nmap_xml)

    assert scan.host_count == 3


def test_a_recognised_but_unimplemented_format_raises_clearly() -> None:
    """OpenVAS is detected so an upload gets a clean 415 rather than a confusing
    parse error further down the pipeline."""
    with pytest.raises(UnsupportedScanFormatError) as err:
        parse("<report/>", ScanFormat.openvas_xml)

    assert "not supported yet" in str(err.value)
