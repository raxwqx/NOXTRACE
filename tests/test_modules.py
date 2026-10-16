from __future__ import annotations

import hashlib
import io
import json
import tempfile
import unittest
from io import BytesIO
from pathlib import Path
from unittest.mock import patch
from contextlib import redirect_stderr
import socket
import threading

from noxtrace.cli import build_parser
from noxtrace.intro import load_intro_frames
from noxtrace.modules.casenote import create_case_note
from noxtrace.modules.codeaudit import audit_source
from noxtrace.modules.dnsintel import analyze_dns
from noxtrace.modules.domain import analyze_domain
from noxtrace.modules.filehash import analyze_file
from noxtrace.modules.ioc import classify_ioc
from noxtrace.modules.ipintel import analyze_ip
from noxtrace.modules.logtriage import triage_log
from noxtrace.modules.passwordaudit import audit_password
from noxtrace.modules.pomaudit import audit_pom
from noxtrace.modules.osvcheck import check_osv
from noxtrace.modules.portscan import DEFAULT_PORTS, MAX_PORTS, parse_ports, scan_tcp
from noxtrace.modules.urlintel import analyze_url
from noxtrace.modules.webaudit import audit_url
from noxtrace.reporting import make_report, json_text, write_html, write_json


class IPTests(unittest.TestCase):
    def test_global_ip_classified_locally(self):
        report = analyze_ip("8.8.8.8")
        self.assertEqual(report["status"], "ok")
        self.assertTrue(report["data"]["is_global"])
        self.assertFalse(report["data"]["is_private"])
        self.assertEqual(report["data"]["ptr_lookup"], "not requested")

    def test_private_ipv4(self):
        self.assertTrue(analyze_ip("192.168.1.1")["data"]["is_private"])

    def test_ipv6(self):
        report = analyze_ip("2001:4860:4860::8888")
        self.assertEqual(report["data"]["version"], 6)

    def test_invalid_ip(self):
        self.assertEqual(analyze_ip("999.9.9.9")["status"], "error")


class DomainAndURLTests(unittest.TestCase):
    def test_domain_normalization(self):
        report = analyze_domain("EXAMPLE.COM.")
        self.assertTrue(report["data"]["syntax_valid"])
        self.assertEqual(report["data"]["normalized_ascii"], "example.com")

    def test_domain_bad_label(self):
        self.assertFalse(analyze_domain("-bad.example")["data"]["syntax_valid"])

    def test_domain_idn(self):
        report = analyze_domain("bücher.example")
        self.assertTrue(report["data"]["syntax_valid"])
        self.assertIn("xn--", report["data"]["normalized_ascii"])

    def test_url_never_fetches(self):
        report = analyze_url("https://example.com/path?q=private#part")
        self.assertFalse(report["data"]["network_request_made"])
        self.assertNotIn("private", report["target"])
        self.assertNotIn("part", report["target"])

    def test_url_credentials_not_in_report_target(self):
        report = analyze_url("https://user:secret@example.com/x")
        self.assertNotIn("secret", report["target"])
        self.assertTrue(report["data"]["userinfo_omitted"])

    def test_url_requires_absolute_http(self):
        self.assertEqual(analyze_url("javascript:alert(1)")["status"], "error")


class PortScanTests(unittest.TestCase):
    def test_default_ports_bounded(self):
        ports = parse_ports(None)
        self.assertEqual(ports, sorted(DEFAULT_PORTS))
        self.assertLessEqual(len(ports), MAX_PORTS)

    def test_range_deduplicates_and_sorts(self):
        self.assertEqual(parse_ports("80,22,80,8000-8002"), [22, 80, 8000, 8001, 8002])

    def test_rejects_invalid_port(self):
        with self.assertRaises(ValueError): parse_ports("0,80")
        with self.assertRaises(ValueError): parse_ports("80,65536")

    def test_rejects_large_range(self):
        with self.assertRaises(ValueError): parse_ports("1-257")

    def test_rejects_malformed_range(self):
        with self.assertRaises(ValueError): parse_ports("12-x")

    def test_scanner_detects_loopback_listener(self):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        def accept_once():
            connection, _ = listener.accept()
            connection.close()
        worker = threading.Thread(target=accept_once, daemon=True)
        worker.start()
        report = scan_tcp("127.0.0.1", [port], timeout=0.5)
        listener.close()
        worker.join(timeout=1)
        self.assertEqual(report["status"], "ok")
        self.assertEqual(report["data"]["open_ports"][0]["port"], port)

    def test_invalid_timeout_stops_before_network(self):
        with patch("noxtrace.modules.portscan.socket.getaddrinfo") as resolver:
            report = scan_tcp("localhost", [80], timeout=99)
        self.assertEqual(report["status"], "error")
        resolver.assert_not_called()


class DNSAndReportTests(unittest.TestCase):
    def test_dns_a_uses_system_resolver(self):
        fake = [(2, 1, 6, "", ("203.0.113.10", 0))]
        with patch("noxtrace.modules.dnsintel.socket.getaddrinfo", return_value=fake):
            report = analyze_dns("sample.invalid", ["A"])
        self.assertEqual(report["data"]["A"], ["203.0.113.10"])

    def test_dns_rejects_unknown_type(self):
        self.assertEqual(analyze_dns("example.com", ["AXFR"])["status"], "error")

    def test_json_roundtrip(self):
        report = make_report("Unit", "test", "ok", "works", {"x": 1})
        self.assertEqual(json.loads(json_text(report))["data"]["x"], 1)

    def test_html_escapes_untrusted_text(self):
        with tempfile.TemporaryDirectory() as td:
            path = write_html(make_report("unit", "<script>", "ok", "<hello>"), Path(td) / "report.html")
            content = path.read_text()
        self.assertNotIn("<script>", content)
        self.assertIn("&lt;script&gt;", content)

    def test_write_json_creates_parent(self):
        with tempfile.TemporaryDirectory() as td:
            path = write_json(make_report("unit", "x", "ok", "y"), Path(td) / "new" / "r.json")
            self.assertTrue(path.exists())


class FileAndLogTests(unittest.TestCase):
    def test_file_hashes(self):
        with tempfile.TemporaryDirectory() as td:
            file = Path(td) / "sample.bin"
            file.write_bytes(b"NOXTRACE")
            report = analyze_file(str(file))
        self.assertEqual(report["data"]["sha256"], hashlib.sha256(b"NOXTRACE").hexdigest())
        self.assertFalse(report["data"]["modified"])

    def test_hash_missing_file(self):
        self.assertEqual(analyze_file("/this/path/does/not/exist")["status"], "error")

    def test_log_triage_does_not_return_full_line(self):
        with tempfile.TemporaryDirectory() as td:
            file = Path(td) / "auth.log"
            file.write_text("Failed password for alice secret-token from 192.0.2.1\n", encoding="utf-8")
            report = triage_log(str(file))
        self.assertEqual(report["data"]["match_count"], 1)
        self.assertNotIn("secret-token", json_text(report))


class OtherModuleTests(unittest.TestCase):
    def test_pom_audit_flags_snapshot(self):
        with tempfile.TemporaryDirectory() as td:
            file = Path(td) / "pom.xml"
            file.write_text('<project><dependencies><dependency><groupId>org.demo</groupId><artifactId>demo</artifactId><version>1-SNAPSHOT</version></dependency></dependencies></project>')
            report = audit_pom(str(file))
        self.assertEqual(report["data"]["dependency_count"], 1)
        self.assertTrue(any("Non-fixed" in item["title"] for item in report["findings"]))

    def test_ioc_hash_syntax(self):
        report = classify_ioc("a" * 64)
        self.assertEqual(report["data"]["likely_algorithm"], "SHA-256")

    def test_case_note(self):
        self.assertEqual(create_case_note("lab", "observed ok")["status"], "ok")
        self.assertEqual(create_case_note("", "")["status"], "error")

    def test_code_audit_detects_review_pattern_without_source_line(self):
        with tempfile.TemporaryDirectory() as td:
            file = Path(td) / "app.py"
            file.write_text("user_input = input()\n" + "eval" + "(user_input)\n", encoding="utf-8")
            report = audit_source(str(file))
        self.assertEqual(report["data"]["matches_count"], 1)
        self.assertEqual(report["data"]["matches"][0]["title"], "Dynamic code evaluation")
        self.assertNotIn("eval(user_input)", json_text(report))

    def test_osv_found_advisory(self):
        payload = {"vulns": [{"id": "GHSA-TEST-1234", "summary": "Sample advisory", "aliases": ["CVE-2099-0001"], "severity": [{"score": "8.1"}]}]}
        with patch("urllib.request.urlopen", return_value=BytesIO(json.dumps(payload).encode())) as open_url:
            report = check_osv("demo-package", "1.2.3", "PyPI")
        self.assertEqual(report["data"]["vulnerability_count"], 1)
        self.assertEqual(report["findings"][0]["title"], "GHSA-TEST-1234")
        self.assertTrue(report["data"]["network_lookup_performed"])
        open_url.assert_called_once()

    def test_osv_empty_result_is_not_claimed_as_proof_of_safety(self):
        with patch("urllib.request.urlopen", return_value=BytesIO(b'{"vulns": []}')):
            report = check_osv("demo-package", "1.2.3", "PyPI")
        self.assertEqual(report["status"], "ok")
        self.assertIn("does not prove", " ".join(report["notes"]))

    def test_password_audit_does_not_store_value(self):
        secret = "Super-Private-Test-Value-" + "987!"
        serialized = json_text(audit_password(secret))
        self.assertNotIn(secret, serialized)
        self.assertIn('"secret_saved": false', serialized)


class WebAuditTests(unittest.TestCase):
    def test_url_credentials_rejected_before_request(self):
        with patch("urllib.request.build_opener") as build:
            report = audit_url("https://user:pass@example.com")
        self.assertEqual(report["status"], "error")
        build.assert_not_called()

    def test_web_header_audit_uses_head_and_reviews_headers(self):
        class Response:
            status = 200
            headers = {"server": "demo", "content-security-policy": "default-src 'self'"}
            def close(self): pass
        class Opener:
            def open(self, request, timeout):
                self.request = request
                self.timeout = timeout
                return Response()
        opener = Opener()
        with patch("urllib.request.build_opener", return_value=opener):
            report = audit_url("https://example.com")
        self.assertEqual(report["data"]["request_method"], "HEAD")
        self.assertFalse(report["data"]["redirects_followed"])
        self.assertTrue(any("Missing" in item["title"] for item in report["findings"]))


class CLIProtectionTests(unittest.TestCase):
    def test_active_scan_requires_authorized_acknowledgement(self):
        parser = build_parser()
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                parser.parse_args(["scan", "127.0.0.1", "--ports", "80"])
        self.assertEqual(error.exception.code, 2)

    def test_osv_requires_online_opt_in(self):
        parser = build_parser()
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                parser.parse_args(["osv-check", "demo", "1.0", "--ecosystem", "PyPI"])
        self.assertEqual(error.exception.code, 2)


class IntroTests(unittest.TestCase):
    def test_bundled_intro_has_multiple_frames(self):
        frames = load_intro_frames()
        self.assertGreaterEqual(len(frames), 20)
        self.assertTrue(all("▀" in frame for frame in frames))

    def test_no_intro_flag_is_available(self):
        args = build_parser().parse_args(["--no-intro"])
        self.assertTrue(args.no_intro)
        self.assertIsNone(args.command)

if __name__ == "__main__":
    unittest.main()

