"""Unit tests for all scanner/tool output parsers.

Each test loads a fixture file and asserts the parser returns the expected
structured data. Tests are pure-Python: no network, no database, no LLM.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.parsers import ParseError, nmap, nuclei, suricata, trivy, zap, zeek
from app.parsers import email as email_parser

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


# ---------------------------------------------------------------------------
# Nmap
# ---------------------------------------------------------------------------

class TestNmapParser:
    def test_parse_xml(self) -> None:
        raw = (FIXTURES / "nmap_sample.xml").read_text()
        hosts = nmap.parse(raw)

        assert len(hosts) == 1
        host = hosts[0]
        assert host.ip == "10.10.1.20"
        assert host.hostname == "server01.internal"
        assert host.state == "up"
        assert "Linux" in host.os_guess

        ports = {s.port: s for s in host.services}
        assert 22 in ports
        ssh = ports[22]
        assert ssh.service == "ssh"
        assert ssh.version == "7.2"
        assert "cpe:/a:openbsd:openssh:7.2" in ssh.cpe
        assert 3306 in ports
        assert ports[3306].service == "mysql"

    def test_parse_empty_raises(self) -> None:
        with pytest.raises(ParseError):
            nmap.parse("")

    def test_parse_grepable(self) -> None:
        raw = (
            "# Nmap 7.94 scan\n"
            "Host: 10.0.0.1 (router.local)\tPorts: 22/open/tcp//ssh//OpenSSH 8.2//, "
            "80/open/tcp//http//Apache 2.4//"
        )
        hosts = nmap.parse(raw)
        assert len(hosts) == 1
        assert hosts[0].ip == "10.0.0.1"
        assert any(s.port == 22 for s in hosts[0].services)

    def test_parse_normal_text(self) -> None:
        raw = (
            "Nmap scan report for 192.168.1.1\n"
            "22/tcp  open  ssh     OpenSSH 8.2\n"
            "80/tcp  open  http    Apache 2.4\n"
        )
        hosts = nmap.parse(raw)
        assert len(hosts) >= 1
        assert any(s.port == 22 for s in hosts[0].services)


# ---------------------------------------------------------------------------
# Trivy
# ---------------------------------------------------------------------------

class TestTrivyParser:
    def test_parse_json(self) -> None:
        raw = (FIXTURES / "trivy_sample.json").read_text()
        report = trivy.parse(raw)

        assert report.artifact_name == "nginx:1.19.0"
        assert len(report.targets) == 1
        vulns = report.targets[0].vulnerabilities
        assert len(vulns) == 2

        cve_ids = {v.vuln_id for v in vulns}
        assert "CVE-2021-23017" in cve_ids
        assert "CVE-2019-20372" in cve_ids

        high = next(v for v in vulns if v.vuln_id == "CVE-2021-23017")
        assert high.severity == "HIGH"
        assert high.cvss_score == 7.7
        assert high.fixed_version == "1.21.0"

    def test_parse_empty_raises(self) -> None:
        with pytest.raises(ParseError):
            trivy.parse("")

    def test_parse_no_vulns(self) -> None:
        import json
        data = {"SchemaVersion": 2, "ArtifactName": "clean:latest",
                "ArtifactType": "container_image", "Results": []}
        report = trivy.parse(json.dumps(data))
        assert report.artifact_name == "clean:latest"
        assert report.targets == []


# ---------------------------------------------------------------------------
# ZAP
# ---------------------------------------------------------------------------

class TestZAPParser:
    def test_parse_json(self) -> None:
        raw = (FIXTURES / "zap_sample.json").read_text()
        report = zap.parse(raw)

        assert "example.com" in report.site
        assert len(report.alerts) == 3

        risks = {a.risk for a in report.alerts}
        assert "High" in risks
        assert "Medium" in risks

        xss = next(a for a in report.alerts if "Cross Site" in a.name)
        assert xss.cwe_id == "79"
        assert len(xss.instances) == 1
        assert xss.instances[0].param == "q"

    def test_owasp_id_extracted(self) -> None:
        raw = (FIXTURES / "zap_sample.json").read_text()
        report = zap.parse(raw)
        owasp_ids = {a.owasp_id for a in report.alerts if a.owasp_id}
        # At least one alert should have an OWASP ID extracted
        assert len(owasp_ids) >= 1

    def test_parse_empty_raises(self) -> None:
        with pytest.raises(ParseError):
            zap.parse("")


# ---------------------------------------------------------------------------
# Nuclei
# ---------------------------------------------------------------------------

class TestNucleiParser:
    def test_parse_ndjson(self) -> None:
        raw = (FIXTURES / "nuclei_sample.json").read_text()
        findings = nuclei.parse(raw)

        assert len(findings) == 3
        severities = {f.severity for f in findings}
        assert "critical" in severities
        assert "high" in severities
        assert "medium" in severities

        crit = next(f for f in findings if f.severity == "critical")
        assert "CVE-2021-41773" in crit.template_id
        assert "apache" in crit.tags

    def test_parse_empty_returns_empty(self) -> None:
        assert nuclei.parse("") == []

    def test_parse_skips_bad_lines(self) -> None:
        raw = 'not json\n{"template-id":"x","info":{"name":"t","severity":"low"},"matched-at":"http://a.com","host":"a.com"}\n'
        findings = nuclei.parse(raw)
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# Zeek
# ---------------------------------------------------------------------------

class TestZeekParser:
    def test_parse_dns_log(self) -> None:
        raw = (FIXTURES / "zeek_dns.log").read_text()
        records = zeek.parse_dns(raw)

        assert len(records) >= 10
        nxdomains = [r for r in records if r.rcode_name == "NXDOMAIN"]
        assert len(nxdomains) >= 9

        # Check random subdomain pattern
        nxdomain_queries = [r.query for r in nxdomains]
        assert any("evil.com" in q for q in nxdomain_queries)

    def test_parse_conn_log(self) -> None:
        # Build a minimal conn.log
        raw = (
            "#separator \\x09\n"
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p"
            "\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state"
            "\tlocal_orig\tlocal_resp\tmissed_bytes\thistory\torig_pkts"
            "\torig_ip_bytes\tresp_pkts\tresp_ip_bytes\n"
            "1700000000.0\tCabc\t10.0.0.1\t12345\t8.8.8.8\t53\tudp\tdns"
            "\t0.001\t100\t200\tSF\tT\tF\t0\tDd\t1\t128\t1\t228\n"
        )
        records = zeek.parse_conn(raw)
        assert len(records) == 1
        assert records[0].orig_h == "10.0.0.1"
        assert records[0].resp_p == 53


# ---------------------------------------------------------------------------
# Suricata
# ---------------------------------------------------------------------------

class TestSuricataParser:
    def test_parse_eve_json(self) -> None:
        raw = (
            '{"event_type":"alert","timestamp":"2026-08-05T10:00:00","flow_id":1,'
            '"src_ip":"192.168.1.50","src_port":45678,"dest_ip":"1.2.3.4",'
            '"dest_port":80,"proto":"TCP","alert":{"signature":"ET TROJAN Beacon",'
            '"signature_id":2034567,"category":"Trojan Activity","severity":1,'
            '"action":"allowed"},"payload_printable":""}\n'
            '{"event_type":"flow","timestamp":"2026-08-05T10:00:01"}\n'
        )
        alerts = suricata.parse(raw)
        assert len(alerts) == 1
        assert alerts[0].signature == "ET TROJAN Beacon"
        assert alerts[0].severity == 1
        assert alerts[0].src_ip == "192.168.1.50"

    def test_non_alert_events_skipped(self) -> None:
        raw = '{"event_type":"flow"}\n{"event_type":"stats"}\n'
        assert suricata.parse(raw) == []

    def test_empty_returns_empty(self) -> None:
        assert suricata.parse("") == []


# ---------------------------------------------------------------------------
# Email
# ---------------------------------------------------------------------------

class TestEmailParser:
    def test_parse_phishing_eml(self) -> None:
        raw = (FIXTURES / "email_phishing.eml").read_text()
        parsed = email_parser.parse(raw)

        # Sender domain should be the spoofed domain, not paypal.com
        assert "paypa1-verify.com" in parsed.sender_domain
        assert parsed.display_name == "PayPal Security Team"

        # Display name says PayPal but domain is different — key mismatch signal
        assert parsed.sender_domain != "paypal.com"

        # Reply-To differs from From domain
        assert parsed.reply_to_domain != "" and parsed.reply_to_domain != parsed.sender_domain

        # Auth failures
        assert parsed.spf_result == "fail"
        assert parsed.dkim_result == "fail"
        assert parsed.dmarc_result == "fail"

        # Links present
        assert len(parsed.links) >= 1
        assert any("paypa1-verify.com" in link for link in parsed.links)

        # Urgency detected
        assert len(parsed.urgency_phrases) >= 2

        # Brand keyword
        assert "paypal" in parsed.brand_keywords

    def test_parse_plain_email(self) -> None:
        raw = (
            "From: alice@example.com\n"
            "To: bob@example.com\n"
            "Subject: Hello\n"
            "Authentication-Results: mx.example.com; spf=pass; dkim=pass; dmarc=pass\n"
            "MIME-Version: 1.0\n"
            "Content-Type: text/plain\n\n"
            "Just a normal email.\n"
        )
        parsed = email_parser.parse(raw)
        assert parsed.spf_result == "pass"
        assert parsed.dkim_result == "pass"
        assert parsed.brand_keywords == []
        assert parsed.urgency_phrases == []
