"""Unit and integration tests for PMFA Core Component 1:
Threat Feed Ingestion & Cryptographic Verification Module.
"""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from pmfa.crypto.signatures import (
    generate_keypair,
    load_private_key,
    load_public_key,
    serialize_private_key,
    serialize_public_key,
    sign_feed_data,
    verify_feed_signature,
)
from pmfa.feed_verifier import (
    E_INTEGRITY_FAIL,
    FeedSchemaError,
    IntegrityVerificationError,
    ThreatFeed,
    sign_feed_file,
    validate_feed_schema,
    verify_and_load_feed,
)


class TestEd25519Signatures(unittest.TestCase):
    """Tests Ed25519 signature generation and verification."""

    def setUp(self):
        self.priv_key, self.pub_key = generate_keypair()
        self.sample_data = b'{"test": "payload", "timestamp": "2026-10-21T00:00:00Z"}'
        self.valid_sig = sign_feed_data(self.priv_key, self.sample_data)

    def test_valid_signature_verification(self):
        result = verify_feed_signature(self.pub_key, self.sample_data, self.valid_sig)
        self.assertTrue(result)

    def test_tampered_data_fails_verification(self):
        tampered = bytearray(self.sample_data)
        tampered[0] = ord(b"X") if tampered[0] != ord(b"X") else ord(b"Y")
        result = verify_feed_signature(self.pub_key, bytes(tampered), self.valid_sig)
        self.assertFalse(result)

    def test_corrupted_signature_fails_verification(self):
        corrupted_sig = bytearray(self.valid_sig)
        corrupted_sig[5] ^= 0xFF
        result = verify_feed_signature(self.pub_key, self.sample_data, bytes(corrupted_sig))
        self.assertFalse(result)

    def test_wrong_public_key_fails_verification(self):
        _, another_pub_key = generate_keypair()
        result = verify_feed_signature(another_pub_key, self.sample_data, self.valid_sig)
        self.assertFalse(result)

    def test_pem_serialization_roundtrip(self):
        priv_pem = serialize_private_key(self.priv_key)
        pub_pem = serialize_public_key(self.pub_key)

        reloaded_priv = load_private_key(priv_pem)
        reloaded_pub = load_public_key(pub_pem)

        new_sig = sign_feed_data(reloaded_priv, self.sample_data)
        self.assertTrue(verify_feed_signature(reloaded_pub, self.sample_data, new_sig))


class TestThreatFeedIngestion(unittest.TestCase):
    """Tests Threat Feed loading, integrity verification, and schema validation."""

    def setUp(self):
        self.workspace_root = Path(__file__).resolve().parent.parent
        self.feed_path = self.workspace_root / "pmfa" / "feeds" / "iocs.json"
        self.sig_path = self.workspace_root / "pmfa" / "feeds" / "iocs.json.sig"
        self.pubkey_path = self.workspace_root / "pmfa" / "keys" / "vendor_public.pem"
        self.privkey_path = self.workspace_root / "pmfa" / "keys" / "vendor_private.pem"

    def test_official_feed_verification_succeeds(self):
        feed = verify_and_load_feed(self.feed_path, self.sig_path, self.pubkey_path)
        self.assertIsInstance(feed, ThreatFeed)
        self.assertEqual(feed.threat_actor, "NSO Group / Pegasus")
        self.assertEqual(feed.version, "1.0.0")
        self.assertGreater(len(feed.hashes_sha256), 0)
        self.assertGreater(len(feed.suspicious_paths), 0)
        self.assertGreater(len(feed.suspicious_filenames), 0)

    def test_threat_feed_membership_checks(self):
        feed = verify_and_load_feed(self.feed_path, self.sig_path, self.pubkey_path)
        # Test hash matching
        known_hash = "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e"
        self.assertTrue(feed.matches_hash(known_hash))
        self.assertTrue(feed.matches_hash(known_hash.upper()))  # Case insensitive
        self.assertFalse(feed.matches_hash("0000000000000000000000000000000000000000000000000000000000000000"))

        # Test filename matching
        self.assertTrue(feed.matches_filename("com.apple.coretelephony.ext"))
        self.assertTrue(feed.matches_filename("libagent_payload.dylib"))
        self.assertFalse(feed.matches_filename("clean_system_file.dylib"))

        # Test path matching
        self.assertTrue(feed.matches_path("/private/var/tmp/com.apple.crashreporter.plist"))
        self.assertTrue(feed.matches_path("/backup/private/var/tmp/com.apple.crashreporter.plist"))
        self.assertFalse(feed.matches_path("/System/Library/clean.plist"))

    def test_tampered_feed_raises_integrity_error(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            tampered_feed = tmp_path / "iocs_tampered.json"
            content = self.feed_path.read_text(encoding="utf-8")
            # Adversary inserts a modified string
            content_tampered = content.replace("NSO Group / Pegasus", "Benign Actor")
            tampered_feed.write_text(content_tampered, encoding="utf-8")

            with self.assertRaises(IntegrityVerificationError):
                verify_and_load_feed(tampered_feed, self.sig_path, self.pubkey_path)

    def test_schema_validation_missing_keys(self):
        bad_payload = {
            "version": "1.0.0",
            "threat_actor": "NSO Group",
            # missing hashes_sha256, suspicious_paths, suspicious_filenames
        }
        with self.assertRaises(FeedSchemaError):
            validate_feed_schema(bad_payload)

    def test_sign_feed_file_helper(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            custom_feed = tmp_path / "custom_iocs.json"
            custom_feed.write_text(self.feed_path.read_text())

            generated_sig = sign_feed_file(custom_feed, self.privkey_path)
            self.assertTrue(generated_sig.is_file())

            feed = verify_and_load_feed(custom_feed, generated_sig, self.pubkey_path)
            self.assertEqual(feed.threat_actor, "NSO Group / Pegasus")

    def test_feed_schema_with_regex_patterns(self):
        valid_payload = {
            "version": "1.0.0",
            "threat_actor": "NSO Group / Pegasus",
            "last_updated": "2026-10-19T00:00:00Z",
            "hashes_sha256": ["a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e"],
            "suspicious_paths": ["/private/var/tmp/stage1.plist"],
            "suspicious_filenames": ["libpayload.dylib"],
            "suspicious_filename_patterns": ["^libagent_.*\\.dylib$"],
            "suspicious_path_patterns": [".*/Preferences/com\\.nso\\..*"],
        }
        feed = validate_feed_schema(valid_payload)
        self.assertIn("^libagent_.*\\.dylib$", feed.suspicious_filename_patterns)
        self.assertEqual(feed.match_filename_pattern("libagent_v2.dylib"), "^libagent_.*\\.dylib$")
        self.assertIsNone(feed.match_filename_pattern("clean_lib.dylib"))
        self.assertEqual(
            feed.match_path_pattern("/Library/Preferences/com.nso.stage2.plist"),
            ".*/Preferences/com\\.nso\\..*",
        )

    def test_feed_schema_invalid_regex_raises_error(self):
        bad_payload = {
            "version": "1.0.0",
            "threat_actor": "NSO Group / Pegasus",
            "last_updated": "2026-10-19T00:00:00Z",
            "hashes_sha256": ["a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e"],
            "suspicious_paths": [],
            "suspicious_filenames": [],
            "suspicious_filename_patterns": ["[invalid_unclosed_regex("],
        }
        with self.assertRaises(FeedSchemaError):
            validate_feed_schema(bad_payload)


class TestCLIIntegrity(unittest.TestCase):
    """Tests CLI entrypoint and exit codes for automated integration."""

    def setUp(self):
        self.workspace_root = Path(__file__).resolve().parent.parent

    def test_cli_success(self):
        cmd = [sys.executable, "-m", "pmfa.feed_verifier"]
        proc = subprocess.run(cmd, cwd=str(self.workspace_root), capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("Threat feed verified via Ed25519", proc.stderr)
        self.assertIn("Verified threat actor : NSO Group / Pegasus", proc.stdout)

    def test_cli_tamper_demo_fails_with_e_integrity_fail(self):
        cmd = [sys.executable, "-m", "pmfa.feed_verifier", "--tamper"]
        proc = subprocess.run(cmd, cwd=str(self.workspace_root), capture_output=True, text=True)
        self.assertEqual(proc.returncode, E_INTEGRITY_FAIL)
        self.assertIn("Cryptographic Verification Failed: Feed signature invalid", proc.stderr)


if __name__ == "__main__":
    unittest.main()
