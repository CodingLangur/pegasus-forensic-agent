"""Unit and integration tests for PMFA Core Component 4:
Evidence Packaging & Cryptographic Sealing Module (AES-256-GCM).
"""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from pmfa.crypto.cipher import (
    AES_KEY_SIZE_BYTES,
    EvidenceTamperingError,
    KeyWrappingError,
    decrypt_report,
    encrypt_report,
    generate_aes_key,
    generate_analyst_keypair,
    load_key,
    save_key,
    unwrap_key_passphrase,
    unwrap_key_rsa,
    wrap_key_passphrase,
    wrap_key_rsa,
)
from pmfa.crypto.signatures import serialize_private_key, serialize_public_key
from pmfa.matcher import Finding, TriageReport
from pmfa.sealer import seal_report, unseal_report


class TestCipherPrimitives(unittest.TestCase):
    """Tests AES-256-GCM authenticated encryption primitives."""

    def test_generate_aes_key(self):
        key = generate_aes_key()
        self.assertEqual(len(key), AES_KEY_SIZE_BYTES)
        # Ensure random keys are distinct
        key2 = generate_aes_key()
        self.assertNotEqual(key, key2)

    def test_encrypt_decrypt_roundtrip(self):
        key = generate_aes_key()
        plaintext = b'{"forensic_test": "tamper_proof", "status": "CONFIDENTIAL"}'
        ciphertext = encrypt_report(plaintext, key)

        # Ciphertext must have 12-byte nonce prepended and 16-byte tag appended
        self.assertEqual(len(ciphertext), len(plaintext) + 12 + 16)

        decrypted = decrypt_report(ciphertext, key)
        self.assertEqual(decrypted, plaintext)

    def test_tampered_ciphertext_fails_aead_tag_verification(self):
        key = generate_aes_key()
        plaintext = b'Sensitive Forensic Evidence'
        ciphertext = bytearray(encrypt_report(plaintext, key))

        # Alter 1 byte in the ciphertext body
        ciphertext[15] ^= 0x55

        with self.assertRaises(EvidenceTamperingError):
            decrypt_report(bytes(ciphertext), key)

    def test_tampered_tag_fails_verification(self):
        key = generate_aes_key()
        plaintext = b'Evidence with valid hash'
        ciphertext = bytearray(encrypt_report(plaintext, key))

        # Alter the last byte (authentication tag)
        ciphertext[-1] ^= 0x01

        with self.assertRaises(EvidenceTamperingError):
            decrypt_report(bytes(ciphertext), key)

    def test_wrong_key_fails_decryption(self):
        key1 = generate_aes_key()
        key2 = generate_aes_key()
        plaintext = b'Confidential Scan'
        ciphertext = encrypt_report(plaintext, key1)

        with self.assertRaises(EvidenceTamperingError):
            decrypt_report(ciphertext, key2)

    def test_key_length_validation(self):
        short_key = b"short_key_16_bytes"[:16]
        with self.assertRaises(ValueError):
            encrypt_report(b"data", short_key)

        with self.assertRaises(ValueError):
            decrypt_report(b"data" * 10, short_key)

    def test_save_and_load_key(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            key_path = Path(tmp_dir) / "test.key"
            key = generate_aes_key()

            # Save as hex
            save_key(key, key_path, as_hex=True)
            loaded = load_key(key_path)
            self.assertEqual(loaded, key)

            # Save as raw binary
            save_key(key, key_path, as_hex=False)
            loaded_raw = load_key(key_path)
            self.assertEqual(loaded_raw, key)


class TestEvidenceSealing(unittest.TestCase):
    """Tests evidence packaging and unsealing workflows."""

    def setUp(self):
        self.sample_report = TriageReport(
            scan_id="urn:uuid:12345678-1234-5678-1234-567812345678",
            timestamp="2026-10-21T07:00:00Z",
            target_path="/test/backup",
            metrics={"files_scanned": 10, "scan_duration_ms": 12.5},
            threat_detected=True,
            findings=[
                Finding(
                    severity="CRITICAL",
                    indicator_type="SHA256_HASH",
                    matched_value="a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e",
                    file_path="payload.bin",
                    file_size_bytes=40960,
                    details="Malicious loader",
                    remediation="Isolate device",
                )
            ],
        )

    def test_seal_and_unseal_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            enc_path = Path(tmp_dir) / "report.enc"
            key_path = Path(tmp_dir) / "report.key"

            pkg = seal_report(
                report_data=self.sample_report,
                output_enc_path=enc_path,
                output_key_path=key_path,
            )

            self.assertTrue(enc_path.is_file())
            self.assertTrue(key_path.is_file())
            self.assertEqual(pkg.ciphertext_size_bytes, enc_path.stat().st_size)

            # Unseal and verify JSON structure
            unsealed = unseal_report(enc_path, key_path)
            self.assertEqual(unsealed["scan_id"], self.sample_report.scan_id)
            self.assertTrue(unsealed["threat_detected"])
            self.assertEqual(len(unsealed["findings"]), 1)
            self.assertEqual(unsealed["findings"][0]["severity"], "CRITICAL")
            self.assertEqual(
                unsealed["findings"][0]["matched_value"],
                "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e",
            )

    def test_unseal_tampered_evidence_file_raises(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            enc_path = Path(tmp_dir) / "report.enc"
            key_path = Path(tmp_dir) / "report.key"

            seal_report(self.sample_report, enc_path, key_path)

            # Tamper with file on disk
            data = bytearray(enc_path.read_bytes())
            data[20] ^= 0xAA
            enc_path.write_bytes(data)

            with self.assertRaises(EvidenceTamperingError):
                unseal_report(enc_path, key_path)


class TestKeyWrapping(unittest.TestCase):
    """Tests key wrapping mechanisms (RSA-OAEP and Passphrase PBKDF2)."""

    def setUp(self):
        self.analyst_priv, self.analyst_pub = generate_analyst_keypair(key_size=2048)
        self.aes_key = generate_aes_key()

    def test_rsa_oaep_wrap_unwrap_roundtrip(self):
        wrapped = wrap_key_rsa(self.aes_key, self.analyst_pub)
        unwrapped = unwrap_key_rsa(wrapped, self.analyst_priv)
        self.assertEqual(unwrapped, self.aes_key)

    def test_rsa_oaep_wrong_privkey_fails(self):
        another_priv, _ = generate_analyst_keypair(key_size=2048)
        wrapped = wrap_key_rsa(self.aes_key, self.analyst_pub)
        with self.assertRaises(KeyWrappingError):
            unwrap_key_rsa(wrapped, another_priv)

    def test_passphrase_wrap_unwrap_roundtrip(self):
        passphrase = "ForensicInvestigator2026!"
        wrapped = wrap_key_passphrase(self.aes_key, passphrase)
        unwrapped = unwrap_key_passphrase(wrapped, passphrase)
        self.assertEqual(unwrapped, self.aes_key)

    def test_passphrase_wrong_passphrase_fails(self):
        wrapped = wrap_key_passphrase(self.aes_key, "CorrectPassword123")
        with self.assertRaises(KeyWrappingError):
            unwrap_key_passphrase(wrapped, "WrongPassword456")

    def test_seal_and_unseal_with_analyst_rsa_key(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            enc_path = Path(tmp_dir) / "report.enc"
            key_path = Path(tmp_dir) / "report.key"
            sample_report = {"scan_id": "test-rsa-wrap", "threat_detected": True}

            pkg = seal_report(
                report_data=sample_report,
                output_enc_path=enc_path,
                output_key_path=key_path,
                analyst_pubkey=self.analyst_pub,
            )
            self.assertTrue(pkg.is_wrapped)
            self.assertEqual(pkg.wrapping_type, "RSA-OAEP")
            self.assertIsNone(pkg.key_hex)

            # Unsealing without private key must fail
            with self.assertRaises(KeyWrappingError):
                unseal_report(enc_path, key_path)

            # Unsealing with analyst private key succeeds
            unsealed = unseal_report(enc_path, key_path, analyst_privkey=self.analyst_priv)
            self.assertEqual(unsealed["scan_id"], "test-rsa-wrap")

    def test_seal_and_unseal_with_passphrase(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            enc_path = Path(tmp_dir) / "report.enc"
            key_path = Path(tmp_dir) / "report.key"
            sample_report = {"scan_id": "test-pass-wrap", "threat_detected": False}

            pkg = seal_report(
                report_data=sample_report,
                output_enc_path=enc_path,
                output_key_path=key_path,
                passphrase="StrongSecretPassphrase",
            )
            self.assertTrue(pkg.is_wrapped)
            self.assertEqual(pkg.wrapping_type, "PASSPHRASE")

            # Unsealing with wrong passphrase fails
            with self.assertRaises(KeyWrappingError):
                unseal_report(enc_path, key_path, passphrase="WrongSecretPassphrase")

            # Unsealing with correct passphrase succeeds
            unsealed = unseal_report(enc_path, key_path, passphrase="StrongSecretPassphrase")
            self.assertEqual(unsealed["scan_id"], "test-pass-wrap")


class TestSealerCLI(unittest.TestCase):
    """Tests CLI entrypoints for report decryption and tamper check."""

    def setUp(self):
        self.workspace_root = Path(__file__).resolve().parent.parent

    def test_cli_seal_and_decrypt(self):
        # 1. Run seal on infected backup
        seal_cmd = [
            sys.executable,
            "-m",
            "pmfa.sealer",
            "--seal",
            "--target",
            "test_fixtures/infected_backup",
        ]
        proc = subprocess.run(seal_cmd, cwd=str(self.workspace_root), capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("Evidence report sealed via AES-256-GCM", proc.stderr)

        # 2. Run --decrypt-report utility
        decrypt_cmd = [
            sys.executable,
            "-m",
            "pmfa.sealer",
            "--decrypt-report",
            "output/report.enc",
            "--key",
            "output/report.key",
        ]
        proc2 = subprocess.run(decrypt_cmd, cwd=str(self.workspace_root), capture_output=True, text=True)
        self.assertEqual(proc2.returncode, 0)
        self.assertIn("AUTHENTICATED FORENSIC REPORT (DECRYPTED EVIDENCE)", proc2.stdout)
        self.assertIn("AEAD Verification: Tag Valid. Chain of custody confirmed.", proc2.stdout)

    def test_cli_tamper_check_demo(self):
        tamper_cmd = [
            sys.executable,
            "-m",
            "pmfa.sealer",
            "--tamper-check",
            "--output-enc",
            "output/report.enc",
            "--key",
            "output/report.key",
        ]
        proc = subprocess.run(tamper_cmd, cwd=str(self.workspace_root), capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("AEAD authentication tag mismatch", proc.stderr)
        self.assertIn("Non-repudiation maintained: Tampered evidence rejected successfully.", proc.stderr)

    def test_cli_seal_and_decrypt_with_analyst_key(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            pub_path = tmp / "analyst_pub.pem"
            priv_path = tmp / "analyst_priv.pem"
            enc_path = tmp / "report.enc"
            key_path = tmp / "report.key"

            priv, pub = generate_analyst_keypair(2048)
            pub_path.write_bytes(serialize_public_key(pub))
            priv_path.write_bytes(serialize_private_key(priv))

            # Seal with analyst pubkey
            seal_cmd = [
                sys.executable,
                "-m",
                "pmfa.sealer",
                "--seal",
                "--target",
                "test_fixtures/clean_backup",
                "--output-enc",
                str(enc_path),
                "--output-key",
                str(key_path),
                "--analyst-pubkey",
                str(pub_path),
            ]
            proc = subprocess.run(seal_cmd, cwd=str(self.workspace_root), capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0)
            self.assertIn("Wrapped Key (RSA-OAEP)", proc.stdout)

            # Decrypt with analyst privkey
            decrypt_cmd = [
                sys.executable,
                "-m",
                "pmfa.sealer",
                "--decrypt-report",
                str(enc_path),
                "--key",
                str(key_path),
                "--analyst-privkey",
                str(priv_path),
            ]
            proc2 = subprocess.run(decrypt_cmd, cwd=str(self.workspace_root), capture_output=True, text=True)
            self.assertEqual(proc2.returncode, 0)
            self.assertIn("AUTHENTICATED FORENSIC REPORT (DECRYPTED EVIDENCE)", proc2.stdout)


if __name__ == "__main__":
    unittest.main()
