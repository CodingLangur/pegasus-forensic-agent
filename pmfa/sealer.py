"""Evidence Packaging & Cryptographic Sealing Module.

Autonomous module that packages forensic triage findings into structured JSON,
seals the report using authenticated symmetric encryption (AES-256-GCM),
and safeguards chain of custody and forensic confidentiality.
"""

from dataclasses import dataclass
import json
import logging
from pathlib import Path
import sys
from typing import Any, Dict, Optional, Tuple, Union

from pmfa.crypto.cipher import (
    AES_KEY_SIZE_BYTES,
    EvidenceTamperingError,
    decrypt_report,
    encrypt_report,
    generate_aes_key,
    load_key,
    save_key,
)
from pmfa.matcher import TriageReport

logger = logging.getLogger("pmfa.sealer")
if not logger.handlers:
    handler = logging.StreamHandler(sys.stderr)
    formatter = logging.Formatter("%(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


@dataclass(frozen=True)
class SealedPackage:
    """Represents a sealed, authenticated forensic package on disk."""
    encrypted_report_path: Path
    key_path: Path
    key_hex: str
    ciphertext_size_bytes: int


def seal_report(
    report_data: Union[TriageReport, Dict[str, Any], bytes, str],
    output_enc_path: Union[str, Path] = "output/report.enc",
    output_key_path: Optional[Union[str, Path]] = "output/report.key",
    key: Optional[bytes] = None,
) -> SealedPackage:
    """Serializes and seals a forensic report using AES-256-GCM.

    Generates a unique 256-bit symmetric key (if not supplied), encrypts the report
    with authenticated integrity protection (12-byte IV + ciphertext + 16-byte tag),
    and writes report.enc and report.key to the designated output paths.
    """
    if isinstance(report_data, TriageReport):
        plaintext_json = report_data.to_json().encode("utf-8")
    elif isinstance(report_data, dict):
        plaintext_json = json.dumps(report_data, indent=2).encode("utf-8")
    elif isinstance(report_data, str):
        plaintext_json = report_data.encode("utf-8")
    elif isinstance(report_data, bytes):
        plaintext_json = report_data
    else:
        raise TypeError(f"Unsupported report_data type: {type(report_data)}")

    # Generate 256-bit AES key if not provided
    aes_key = key if key is not None else generate_aes_key()
    if len(aes_key) != AES_KEY_SIZE_BYTES:
        raise ValueError(f"AES key must be {AES_KEY_SIZE_BYTES} bytes, got {len(aes_key)}")

    # Encrypt via AES-256-GCM (Nonce || Ciphertext || Tag)
    encrypted_payload = encrypt_report(plaintext_json, aes_key)

    enc_file = Path(output_enc_path)
    enc_file.parent.mkdir(parents=True, exist_ok=True)
    enc_file.write_bytes(encrypted_payload)

    key_file = Path(output_key_path) if output_key_path else enc_file.with_suffix(".key")
    save_key(aes_key, key_file, as_hex=True)

    logger.info("[+] Evidence report sealed via AES-256-GCM -> %s", enc_file)
    logger.info("[+] Ephemeral decryption key saved -> %s", key_file)

    return SealedPackage(
        encrypted_report_path=enc_file,
        key_path=key_file,
        key_hex=aes_key.hex(),
        ciphertext_size_bytes=len(encrypted_payload),
    )


def unseal_report(
    encrypted_source: Union[str, Path, bytes],
    key_source: Union[str, Path, bytes],
) -> Dict[str, Any]:
    """Decrypts and authenticates a sealed forensic report.

    Validates the 128-bit AEAD authentication tag to guarantee non-repudiation
    and detect any adversary tampering in transit.
    """
    if isinstance(encrypted_source, (str, Path)):
        payload_bytes = Path(encrypted_source).read_bytes()
    else:
        payload_bytes = encrypted_source

    if isinstance(key_source, (str, Path)):
        key_bytes = load_key(key_source)
    else:
        key_bytes = key_source

    decrypted_bytes = decrypt_report(payload_bytes, key_bytes)
    return json.loads(decrypted_bytes.decode("utf-8"))


def main() -> int:
    """CLI utility for evidence packaging, sealing, and inspection."""
    import argparse

    parser = argparse.ArgumentParser(
        description="PMFA Evidence Packaging & Cryptographic Sealing Module (AES-256-GCM)"
    )
    parser.add_argument(
        "--decrypt-report",
        metavar="REPORT_ENC",
        help="Path to encrypted forensic report (report.enc) to decrypt and display",
    )
    parser.add_argument(
        "--key",
        metavar="KEY_FILE",
        default="output/report.key",
        help="Path to AES-256 decryption key file (default: output/report.key)",
    )
    parser.add_argument(
        "--seal",
        action="store_true",
        help="Scan and seal forensic evidence from target backup into output/report.enc",
    )
    parser.add_argument(
        "--target",
        help="Target device backup directory to scan and seal (used with --seal)",
    )
    parser.add_argument(
        "--feed",
        default="pmfa/feeds/iocs.json",
        help="Threat feed path (default: pmfa/feeds/iocs.json)",
    )
    parser.add_argument(
        "--sig",
        default="pmfa/feeds/iocs.json.sig",
        help="Threat feed signature path (default: pmfa/feeds/iocs.json.sig)",
    )
    parser.add_argument(
        "--pubkey",
        default="pmfa/keys/vendor_public.pem",
        help="Vendor public key path (default: pmfa/keys/vendor_public.pem)",
    )
    parser.add_argument(
        "--output-enc",
        default="output/report.enc",
        help="Output path for encrypted report (default: output/report.enc)",
    )
    parser.add_argument(
        "--output-key",
        default="output/report.key",
        help="Output path for decryption key (default: output/report.key)",
    )
    parser.add_argument(
        "--tamper-check",
        action="store_true",
        help="Demonstrate AEAD integrity failure by altering 1 byte of encrypted report",
    )

    args = parser.parse_args()

    # Mode 1: Decrypt and inspect sealed report (--decrypt-report)
    if args.decrypt_report:
        try:
            report_dict = unseal_report(args.decrypt_report, args.key)
            print("=" * 72)
            print("         AUTHENTICATED FORENSIC REPORT (DECRYPTED EVIDENCE)       ")
            print("=" * 72)
            print(json.dumps(report_dict, indent=2))
            print("=" * 72)
            print("[+] AEAD Verification: Tag Valid. Chain of custody confirmed.")
            return 0
        except EvidenceTamperingError as exc:
            sys.stderr.write(f"[-] INTEGRITY VIOLATION: {exc}\n")
            return 2
        except Exception as exc:
            sys.stderr.write(f"[-] Decryption error: {exc}\n")
            return 1

    # Mode 2: Tamper Check Demonstration
    if args.tamper_check:
        enc_file = Path(args.output_enc)
        key_file = Path(args.key)
        if not enc_file.is_file() or not key_file.is_file():
            sys.stderr.write("[-] Both output/report.enc and key file must exist for tamper-check\n")
            return 1

        print("[*] Running Evidence Tamper Check Demo (Simulating corrupted/altered ciphertext)...")
        data = bytearray(enc_file.read_bytes())
        # Alter a byte in the ciphertext payload
        data[-1] ^= 0xFF
        try:
            unseal_report(bytes(data), key_file)
            print("[-] UNEXPECTED: Tampered evidence passed AEAD tag verification!")
            return 1
        except EvidenceTamperingError:
            sys.stderr.write("[-] Cryptographic Verification Failed: AEAD authentication tag mismatch.\n")
            sys.stderr.write("[+] Non-repudiation maintained: Tampered evidence rejected successfully.\n")
            return 0

    # Mode 3: Scan, Correlate, and Seal
    if args.seal:
        if not args.target:
            sys.stderr.write("[-] --target path required when using --seal\n")
            return 1

        from pmfa.feed_verifier import verify_and_load_feed
        from pmfa.matcher import IoCMatcher
        from pmfa.scanner import scan_directory

        # Step 1: Ingest and verify threat feed
        feed = verify_and_load_feed(args.feed, args.sig, args.pubkey)

        # Step 2: Scan backup artifacts
        scan_res = scan_directory(args.target)

        # Step 3: Correlate IoCs
        matcher = IoCMatcher(feed)
        report = matcher.correlate_scan(scan_res)

        # Step 4: Seal report under AES-256-GCM
        pkg = seal_report(
            report_data=report,
            output_enc_path=args.output_enc,
            output_key_path=args.output_key,
        )
        print(f"[+] Scan completed       : {report.metrics.get('files_scanned', 0)} files scanned")
        print(f"[+] Threats detected     : {report.threat_detected}")
        print(f"[+] Encrypted Evidence   : {pkg.encrypted_report_path} ({pkg.ciphertext_size_bytes} bytes)")
        print(f"[+] Ephemeral Key        : {pkg.key_path}")
        return 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
