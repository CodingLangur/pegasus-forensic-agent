"""Unit and integration tests for PMFA Core Component 3:
Agent Logic & IoC Matching Engine.
"""

import json
from pathlib import Path
import re
import subprocess
import sys
import unittest

from pmfa.feed_verifier import ThreatFeed, verify_and_load_feed
from pmfa.matcher import Finding, IoCMatcher, TriageReport
from pmfa.scanner import ForensicArtifact, scan_directory


class TestIoCMatcherUnit(unittest.TestCase):
    """Unit tests for individual match vectors in IoCMatcher."""

    def setUp(self):
        self.mock_feed = ThreatFeed(
            version="1.0.0",
            threat_actor="NSO Group / Pegasus",
            last_updated="2026-10-19T00:00:00Z",
            hashes_sha256={"a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e"},
            suspicious_paths={"/private/var/tmp/com.apple.crashreporter.plist"},
            suspicious_filenames={"libagent_payload.dylib"},
            suspicious_domains={"c2-malicious-sink.org"},
            suspicious_filename_patterns={"^payload_v[0-9]+\\.dylib$"},
            suspicious_path_patterns={r".*/var/mobile/Containers/.*"},
            compiled_filename_patterns=[("^payload_v[0-9]+\\.dylib$", re.compile(r"^payload_v[0-9]+\.dylib$", re.IGNORECASE))],
            compiled_path_patterns=[(r".*/var/mobile/Containers/.*", re.compile(r".*/var/mobile/Containers/.*", re.IGNORECASE))],
        )
        self.matcher = IoCMatcher(self.mock_feed)

    def test_vector1_hash_match(self):
        artifact = ForensicArtifact(
            absolute_path="/tmp/test/payload_bin",
            relative_path="payload_bin",
            file_size_bytes=40960,
            sha256="a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e",
            mtime=1700000000.0,
            ctime=1700000000.0,
            mtime_iso="2023-11-14T22:13:20+00:00",
            ctime_iso="2023-11-14T22:13:20+00:00",
            permissions_octal="0o755",
            permissions_symbolic="-rwxr-xr-x",
            file_type="binary",
        )
        finding = self.matcher.match_hash(artifact)
        self.assertIsNotNone(finding)
        self.assertEqual(finding.severity, "CRITICAL")
        self.assertEqual(finding.indicator_type, "SHA256_HASH")
        self.assertEqual(finding.matched_value, artifact.sha256)

    def test_vector1_hash_no_match(self):
        artifact = ForensicArtifact(
            absolute_path="/tmp/test/clean_bin",
            relative_path="clean_bin",
            file_size_bytes=1024,
            sha256="0000000000000000000000000000000000000000000000000000000000000000",
            mtime=1700000000.0,
            ctime=1700000000.0,
            mtime_iso="2023-11-14T22:13:20+00:00",
            ctime_iso="2023-11-14T22:13:20+00:00",
            permissions_octal="0o644",
            permissions_symbolic="-rw-r--r--",
            file_type="binary",
        )
        self.assertIsNone(self.matcher.match_hash(artifact))

    def test_vector2a_filename_match(self):
        artifact = ForensicArtifact(
            absolute_path="/tmp/test/libagent_payload.dylib",
            relative_path="usr/lib/libagent_payload.dylib",
            file_size_bytes=2048,
            sha256="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            mtime=1700000000.0,
            ctime=1700000000.0,
            mtime_iso="2023-11-14T22:13:20+00:00",
            ctime_iso="2023-11-14T22:13:20+00:00",
            permissions_octal="0o644",
            permissions_symbolic="-rw-r--r--",
            file_type="binary",
        )
        finding = self.matcher.match_filename(artifact)
        self.assertIsNotNone(finding)
        self.assertEqual(finding.severity, "CRITICAL")
        self.assertEqual(finding.indicator_type, "SUSPICIOUS_FILENAME")
        self.assertEqual(finding.matched_value, "libagent_payload.dylib")

    def test_vector2b_path_match(self):
        artifact = ForensicArtifact(
            absolute_path="/backup/private/var/tmp/com.apple.crashreporter.plist",
            relative_path="private/var/tmp/com.apple.crashreporter.plist",
            file_size_bytes=512,
            sha256="eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            mtime=1700000000.0,
            ctime=1700000000.0,
            mtime_iso="2023-11-14T22:13:20+00:00",
            ctime_iso="2023-11-14T22:13:20+00:00",
            permissions_octal="0o644",
            permissions_symbolic="-rw-r--r--",
            file_type="plist",
        )
        finding = self.matcher.match_path(artifact)
        self.assertIsNotNone(finding)
        self.assertEqual(finding.severity, "CRITICAL")
        self.assertEqual(finding.indicator_type, "SUSPICIOUS_PATH")

    def test_vector2a_filename_regex_match(self):
        artifact = ForensicArtifact(
            absolute_path="/tmp/test/payload_v2.dylib",
            relative_path="usr/lib/payload_v2.dylib",
            file_size_bytes=2048,
            sha256="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            mtime=1700000000.0,
            ctime=1700000000.0,
            mtime_iso="2023-11-14T22:13:20+00:00",
            ctime_iso="2023-11-14T22:13:20+00:00",
            permissions_octal="0o644",
            permissions_symbolic="-rw-r--r--",
            file_type="binary",
        )
        finding = self.matcher.match_filename(artifact)
        self.assertIsNotNone(finding)
        self.assertEqual(finding.severity, "CRITICAL")
        self.assertEqual(finding.indicator_type, "SUSPICIOUS_FILENAME")
        self.assertIn("regex pattern", finding.details)

    def test_vector2b_path_regex_match(self):
        artifact = ForensicArtifact(
            absolute_path="/backup/private/var/mobile/Containers/Data/Application/malicious.dylib",
            relative_path="private/var/mobile/Containers/Data/Application/malicious.dylib",
            file_size_bytes=1024,
            sha256="dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            mtime=1700000000.0,
            ctime=1700000000.0,
            mtime_iso="2023-11-14T22:13:20+00:00",
            ctime_iso="2023-11-14T22:13:20+00:00",
            permissions_octal="0o644",
            permissions_symbolic="-rw-r--r--",
            file_type="binary",
        )
        finding = self.matcher.match_path(artifact)
        self.assertIsNotNone(finding)
        self.assertEqual(finding.severity, "CRITICAL")
        self.assertEqual(finding.indicator_type, "SUSPICIOUS_PATH")
        self.assertIn("regex pattern", finding.details)


class TestIoCMatcherIntegration(unittest.TestCase):
    """Integration tests correlating full backup scans against official verified feed."""

    def setUp(self):
        self.workspace_root = Path(__file__).resolve().parent.parent
        self.feed_path = self.workspace_root / "pmfa" / "feeds" / "iocs.json"
        self.sig_path = self.workspace_root / "pmfa" / "feeds" / "iocs.json.sig"
        self.pubkey_path = self.workspace_root / "pmfa" / "keys" / "vendor_public.pem"
        self.clean_backup = self.workspace_root / "test_fixtures" / "clean_backup"
        self.infected_backup = self.workspace_root / "test_fixtures" / "infected_backup"

        self.feed = verify_and_load_feed(self.feed_path, self.sig_path, self.pubkey_path)
        self.matcher = IoCMatcher(self.feed)

    def test_clean_backup_has_zero_matches(self):
        scan_result = scan_directory(self.clean_backup)
        report = self.matcher.correlate_scan(scan_result)

        self.assertFalse(report.threat_detected)
        self.assertEqual(len(report.findings), 0)
        self.assertEqual(report.metrics["files_scanned"], 6)

    def test_infected_backup_detects_all_vectors(self):
        scan_result = scan_directory(self.infected_backup)
        report = self.matcher.correlate_scan(scan_result)

        self.assertTrue(report.threat_detected)
        self.assertGreater(len(report.findings), 0)

        indicator_types = {f.indicator_type for f in report.findings}
        self.assertIn("SHA256_HASH", indicator_types)
        self.assertIn("SUSPICIOUS_FILENAME", indicator_types)
        self.assertIn("SUSPICIOUS_PATH", indicator_types)
        self.assertIn("NETWORK_DOMAIN", indicator_types)

        # Check domain offset
        net_finding = next(f for f in report.findings if f.indicator_type == "NETWORK_DOMAIN")
        self.assertIsNotNone(net_finding.byte_offset)
        self.assertEqual(net_finding.matched_value, "cloud-services-sync.net")

    def test_report_schema_compliance(self):
        scan_result = scan_directory(self.infected_backup)
        report = self.matcher.correlate_scan(scan_result)
        report_dict = report.to_dict()

        self.assertTrue(report_dict["scan_id"].startswith("urn:uuid:"))
        self.assertIn("timestamp", report_dict)
        self.assertIn("target_path", report_dict)
        self.assertIn("metrics", report_dict)
        self.assertIn("files_scanned", report_dict["metrics"])
        self.assertIn("scan_duration_ms", report_dict["metrics"])
        self.assertTrue(report_dict["threat_detected"])
        self.assertIsInstance(report_dict["findings"], list)

        first_finding = report_dict["findings"][0]
        self.assertIn("severity", first_finding)
        self.assertIn("indicator_type", first_finding)
        self.assertIn("matched_value", first_finding)
        self.assertIn("file_path", first_finding)
        self.assertIn("file_size_bytes", first_finding)


class TestMatcherCLI(unittest.TestCase):
    """Tests CLI entrypoint for IoC matcher."""

    def setUp(self):
        self.workspace_root = Path(__file__).resolve().parent.parent

    def test_cli_clean_summary(self):
        cmd = [
            sys.executable,
            "-m",
            "pmfa.matcher",
            "--target",
            "test_fixtures/clean_backup",
        ]
        proc = subprocess.run(cmd, cwd=str(self.workspace_root), capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("100% Clean | 0 IOC Matches", proc.stdout)

    def test_cli_infected_summary(self):
        cmd = [
            sys.executable,
            "-m",
            "pmfa.matcher",
            "--target",
            "test_fixtures/infected_backup",
        ]
        proc = subprocess.run(cmd, cwd=str(self.workspace_root), capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("ALERT: Threat Detected", proc.stdout)

    def test_cli_json_mode(self):
        cmd = [
            sys.executable,
            "-m",
            "pmfa.matcher",
            "--target",
            "test_fixtures/infected_backup",
            "--json",
        ]
        proc = subprocess.run(cmd, cwd=str(self.workspace_root), capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0)
        # Parse output JSON (skip logging lines from stderr if any)
        payload = json.loads(proc.stdout)
        self.assertTrue(payload["threat_detected"])
        self.assertGreater(len(payload["findings"]), 0)


if __name__ == "__main__":
    unittest.main()
