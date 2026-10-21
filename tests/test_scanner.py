"""Unit and integration tests for PMFA Core Component 2:
Forensic Inspection & Hashing Engine (SHA-256).
"""

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from pmfa.crypto.hashing import DEFAULT_CHUNK_SIZE, compute_sha256, compute_sha256_bytes
from pmfa.scanner import (
    ForensicArtifact,
    ScanResult,
    classify_file_type,
    inspect_file,
    scan_directory,
)


class TestCryptoHashing(unittest.TestCase):
    """Tests for streaming SHA-256 hashing."""

    def test_empty_file_hash(self):
        with tempfile.NamedTemporaryFile() as tmp:
            expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            actual = compute_sha256(tmp.name)
            self.assertEqual(actual, expected)

    def test_bytes_hash(self):
        data = b"Pegasus Forensic Analysis"
        expected = hashlib.sha256(data).hexdigest()
        self.assertEqual(compute_sha256_bytes(data), expected)

    def test_multichunk_streaming_consistency(self):
        # Create a 256 KB file
        payload = b"A" * 1024 * 256
        with tempfile.NamedTemporaryFile() as tmp:
            tmp.write(payload)
            tmp.flush()

            expected = hashlib.sha256(payload).hexdigest()
            # Test default chunk size
            self.assertEqual(compute_sha256(tmp.name, chunk_size=DEFAULT_CHUNK_SIZE), expected)
            # Test smaller 1 KB chunk size
            self.assertEqual(compute_sha256(tmp.name, chunk_size=1024), expected)
            # Test odd chunk size
            self.assertEqual(compute_sha256(tmp.name, chunk_size=3333), expected)

    def test_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            compute_sha256("/non/existent/path/for/sure/12345.dat")


class TestForensicScanner(unittest.TestCase):
    """Tests for file inspection and directory traversal."""

    def setUp(self):
        self.workspace_root = Path(__file__).resolve().parent.parent
        self.clean_backup = self.workspace_root / "test_fixtures" / "clean_backup"
        self.infected_backup = self.workspace_root / "test_fixtures" / "infected_backup"

    def test_classify_file_type(self):
        self.assertEqual(classify_file_type(Path("Info.plist")), "plist")
        self.assertEqual(classify_file_type(Path("libpayload.dylib")), "binary")
        self.assertEqual(classify_file_type(Path("sms.db")), "database")
        self.assertEqual(classify_file_type(Path("console.log")), "log")
        self.assertEqual(classify_file_type(Path("data.bin")), "binary")

    def test_inspect_single_file(self):
        manifest = self.clean_backup / "Manifest.plist"
        artifact = inspect_file(manifest, base_dir=self.clean_backup)

        self.assertIsInstance(artifact, ForensicArtifact)
        self.assertEqual(artifact.relative_path, "Manifest.plist")
        self.assertEqual(artifact.file_type, "plist")
        self.assertGreater(artifact.file_size_bytes, 0)
        self.assertEqual(len(artifact.sha256), 64)
        self.assertTrue(artifact.permissions_octal.startswith("0o"))
        self.assertTrue(artifact.mtime_iso.endswith("+00:00"))

    def test_scan_clean_backup_directory(self):
        result = scan_directory(self.clean_backup, max_workers=2)
        self.assertIsInstance(result, ScanResult)
        self.assertEqual(result.metrics.files_scanned, 6)
        self.assertEqual(result.metrics.errors_encountered, 0)
        self.assertGreater(result.metrics.total_bytes_scanned, 0)
        self.assertGreater(result.metrics.scan_duration_ms, 0)

        rel_paths = {a.relative_path for a in result.artifacts}
        self.assertIn("Manifest.plist", rel_paths)
        self.assertIn("Info.plist", rel_paths)
        self.assertIn("Status.plist", rel_paths)
        self.assertIn("Library/Preferences/com.apple.mobilesafari.plist", rel_paths)
        self.assertIn("Library/SMS/sms.db", rel_paths)

    def test_scan_infected_backup_directory(self):
        result = scan_directory(self.infected_backup, max_workers=4)
        self.assertEqual(result.metrics.files_scanned, 8)
        self.assertEqual(result.metrics.errors_encountered, 0)

        rel_paths = {a.relative_path for a in result.artifacts}
        self.assertIn("private/var/tmp/com.apple.crashreporter.plist", rel_paths)
        self.assertIn("Library/Preferences/com.nso.stage2.plist", rel_paths)
        self.assertIn("System/Library/Extensions/com.apple.coretelephony.ext", rel_paths)
        self.assertIn("usr/lib/libagent_payload.dylib", rel_paths)
        self.assertIn("zero_trigger.bin", rel_paths)
        self.assertIn("Library/Caches/com.apple.WebKit.Networking/network_cache.db", rel_paths)

        # Verify the empty zero_trigger.bin has expected e3b0c44... hash
        zero_artifact = next(a for a in result.artifacts if a.relative_path == "zero_trigger.bin")
        self.assertEqual(
            zero_artifact.sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )

    def test_multithreaded_vs_sequential_consistency(self):
        seq_result = scan_directory(self.clean_backup, max_workers=1)
        par_result = scan_directory(self.clean_backup, max_workers=8)

        self.assertEqual(seq_result.metrics.files_scanned, par_result.metrics.files_scanned)
        self.assertEqual(seq_result.metrics.total_bytes_scanned, par_result.metrics.total_bytes_scanned)

        seq_hashes = [a.sha256 for a in seq_result.artifacts]
        par_hashes = [a.sha256 for a in par_result.artifacts]
        self.assertEqual(seq_hashes, par_hashes)

    def test_invalid_target_paths(self):
        with self.assertRaises(FileNotFoundError):
            scan_directory("/path/does/not/exist/999")

        manifest = self.clean_backup / "Manifest.plist"
        with self.assertRaises(NotADirectoryError):
            scan_directory(manifest)


class TestScannerCLI(unittest.TestCase):
    """Tests CLI entrypoint for scanner."""

    def setUp(self):
        self.workspace_root = Path(__file__).resolve().parent.parent

    def test_cli_summary_output(self):
        cmd = [
            sys.executable,
            "-m",
            "pmfa.scanner",
            "--target",
            "test_fixtures/clean_backup",
        ]
        proc = subprocess.run(cmd, cwd=str(self.workspace_root), capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("[+] Files Fingerprinted  : 6", proc.stdout)
        self.assertIn("Sample Discovered Artifacts:", proc.stdout)

    def test_cli_json_output(self):
        cmd = [
            sys.executable,
            "-m",
            "pmfa.scanner",
            "--target",
            "test_fixtures/clean_backup",
            "--json",
        ]
        proc = subprocess.run(cmd, cwd=str(self.workspace_root), capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0)
        data = json.loads(proc.stdout)
        self.assertEqual(data["artifacts_count"], 6)
        self.assertIn("metrics", data)
        self.assertEqual(data["metrics"]["files_scanned"], 6)


if __name__ == "__main__":
    unittest.main()
