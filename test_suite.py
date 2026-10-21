"""Regression tests for the PHP2Shell detection suite."""

from __future__ import annotations

import types
import unittest
import json
import tempfile
from pathlib import Path
from unittest import mock

import php_binary_check as binary
import php_cve_audit_local as local
import php_cve_scanner as network


ROOT = Path(__file__).resolve().parent


class BinaryEvidenceTests(unittest.TestCase):
    def test_non_binary_is_not_applicable(self):
        result = binary.check_file(ROOT / "README.md")
        self.assertFalse(result["applicable"])
        self.assertEqual(result["verdict"], "NOT_PHP_RUNTIME")
        self.assertIsNone(result["patched"])

    def test_bundled_controls(self):
        expected = {
            "debian12-php8.2-8.2.34": False,
            "debian12-php8.2-8.2.35": True,
            "remi-el9-php-8.2.34": False,
            "remi-el9-php-8.2.35": True,
        }
        for name, present in expected.items():
            with self.subTest(name=name):
                result = binary.check_file(ROOT / "distro-binaries" / name)
                self.assertTrue(result["applicable"])
                self.assertIs(result["oom_fix_signatures"], present)
                self.assertIsNone(result["patched"])

    def test_php_runtime_filename_recognises_versioned_modules(self):
        self.assertIsNotNone(binary.PHP_FILENAME_RE.search("libphp8.2.so"))
        self.assertIsNotNone(binary.PHP_FILENAME_RE.search("php8.3-fpm"))


class NetworkTests(unittest.TestCase):
    def test_lowercase_header_is_detected(self):
        response = (200, {"x-powered-by": ["PHP/8.2.34"]}, b"")
        with mock.patch.object(network, "make_request", return_value=response):
            result = network.probe_http("host", 80, "http", ["/"], 1, True)
        self.assertIsNotNone(result)
        self.assertTrue(result.vulnerable)

    def test_cookie_value_is_redacted(self):
        secret = "sensitive-session-value"
        response = (200, {"set-cookie": [f"PHPSESSID={secret}; Path=/; HttpOnly"]}, b"")
        with mock.patch.object(network, "make_request", return_value=response):
            result = network.probe_http("host", 80, "http", ["/"], 1, True)
        self.assertIsNotNone(result)
        self.assertNotIn(secret, result.evidence)
        self.assertIn("<redacted>", result.evidence)

    def test_prerelease_is_not_marked_safe(self):
        match = network.VERSION_RE.search("PHP/8.5.12RC1")
        result = network._finding_from_match("host", 80, "http", "/", match, "test")
        self.assertIsNone(result.vulnerable)

    def test_new_branch_is_not_marked_vulnerable(self):
        match = network.VERSION_RE.search("PHP/8.6.0")
        result = network._finding_from_match("host", 80, "http", "/", match, "test")
        self.assertIsNone(result.vulnerable)

    def test_large_cidr_is_refused(self):
        args = types.SimpleNamespace(target=None, subnet="10.0.0.0/8", max_hosts=1024)
        with self.assertRaises(ValueError):
            network.expand_targets(args)

    def test_scanner_has_no_php_cgi_option_probes(self):
        source = (ROOT / "php_cve_scanner.py").read_text(encoding="utf-8")
        self.assertNotIn('"?-s"', source)
        self.assertNotIn('"?-d"', source)
        self.assertNotIn('"?-v"', source)

    def test_empty_scan_writes_empty_json_and_fails_coverage(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "findings.json"
            with mock.patch.object(network, "probe_host", return_value=([], 0)):
                code = network.main([
                    "--target", "192.0.2.1", "--port", "80", "--http",
                    "--output", str(output),
                ])
            self.assertEqual(code, 1)
            self.assertEqual(json.loads(output.read_text(encoding="utf-8")), [])


class LocalAuditTests(unittest.TestCase):
    def test_phpmyadmin_is_not_a_runtime_package(self):
        self.assertIsNone(local.DEB_RUNTIME_PACKAGE_RE.match("phpmyadmin"))

    def test_supported_fixed_version(self):
        result = local._classify("8.4.27", "test", "test")
        self.assertFalse(result.vulnerable)

    def test_future_branch_requires_review(self):
        result = local._classify("8.6.0", "test", "test")
        self.assertIsNone(result.vulnerable)

    def test_prerelease_requires_review(self):
        result = local._classify("8.5.12RC1", "test", "test")
        self.assertIsNone(result.vulnerable)


if __name__ == "__main__":
    unittest.main()

