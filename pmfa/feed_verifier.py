"""Threat Feed Ingestion & Cryptographic Verification Module.

Autonomous module responsible for ingesting threat intelligence indicators (iocs.json),
verifying authenticity against a trusted vendor public key using Ed25519 detached signatures,
and indexing verified rulesets in memory for downstream forensic correlation.
"""

from dataclasses import dataclass, field
import json
import logging
from pathlib import Path
import sys
from typing import Any, Dict, Optional, Set, Union

from pmfa.crypto.signatures import (
    load_private_key,
    load_public_key,
    sign_feed_data,
    verify_feed_signature,
)

# Exit code on cryptographic verification failure (as specified in Design Doc Section 3)
E_INTEGRITY_FAIL = 2

# Configure logger
logger = logging.getLogger("pmfa.feed_verifier")
if not logger.handlers:
    handler = logging.StreamHandler(sys.stderr)
    formatter = logging.Formatter("%(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


class IntegrityVerificationError(Exception):
    """Raised when digital signature verification of threat intelligence fails."""
    pass


class FeedSchemaError(Exception):
    """Raised when threat feed JSON structure fails validation."""
    pass


@dataclass(frozen=True)
class ThreatFeed:
    """Indexed threat intelligence ruleset verified against vendor key."""
    version: str
    threat_actor: str
    last_updated: str
    hashes_sha256: Set[str] = field(default_factory=set)
    suspicious_paths: Set[str] = field(default_factory=set)
    suspicious_filenames: Set[str] = field(default_factory=set)
    suspicious_domains: Set[str] = field(default_factory=set)
    raw_payload: Dict[str, Any] = field(default_factory=dict, repr=False)

    def matches_hash(self, sha256_hash: str) -> bool:
        """Fast O(1) membership check for SHA-256 fingerprint."""
        return sha256_hash.strip().lower() in self.hashes_sha256

    def matches_filename(self, filename: str) -> bool:
        """Fast O(1) membership check for known malicious filename."""
        return filename.strip() in self.suspicious_filenames

    def matches_path(self, path: str) -> bool:
        """Checks if a target path matches or contains any known suspicious path."""
        norm_path = path.strip()
        return any(sp in norm_path for sp in self.suspicious_paths)

    def matches_domain(self, domain: str) -> bool:
        """Checks if a given domain matches any verified suspicious domain."""
        return domain.strip().lower() in self.suspicious_domains


def validate_feed_schema(payload: Dict[str, Any]) -> ThreatFeed:
    """Validates raw dictionary against Section 5.1 Threat Feed Schema."""
    required_fields = [
        "version",
        "threat_actor",
        "last_updated",
        "hashes_sha256",
        "suspicious_paths",
        "suspicious_filenames",
    ]
    missing = [f for f in required_fields if f not in payload]
    if missing:
        raise FeedSchemaError(f"Missing required threat feed fields: {', '.join(missing)}")

    if not isinstance(payload["hashes_sha256"], list):
        raise FeedSchemaError("'hashes_sha256' must be a list of SHA-256 hex strings")
    if not isinstance(payload["suspicious_paths"], list):
        raise FeedSchemaError("'suspicious_paths' must be a list of path strings")
    if not isinstance(payload["suspicious_filenames"], list):
        raise FeedSchemaError("'suspicious_filenames' must be a list of filename strings")

    # Normalize hashes to lowercase and index into sets
    normalized_hashes = {h.strip().lower() for h in payload["hashes_sha256"] if isinstance(h, str)}
    normalized_paths = {p.strip() for p in payload["suspicious_paths"] if isinstance(p, str)}
    normalized_filenames = {fn.strip() for fn in payload["suspicious_filenames"] if isinstance(fn, str)}
    raw_domains = payload.get("suspicious_domains", [])
    normalized_domains = {d.strip().lower() for d in raw_domains if isinstance(d, str)}

    return ThreatFeed(
        version=str(payload["version"]),
        threat_actor=str(payload["threat_actor"]),
        last_updated=str(payload["last_updated"]),
        hashes_sha256=normalized_hashes,
        suspicious_paths=normalized_paths,
        suspicious_filenames=normalized_filenames,
        suspicious_domains=normalized_domains,
        raw_payload=payload,
    )


def verify_and_load_feed(
    feed_path: Union[str, Path],
    signature_path: Union[str, Path],
    public_key_path: Union[str, Path],
) -> ThreatFeed:
    """Verifies threat feed integrity using Ed25519 and loads indexed IoCs.

    Halts execution / raises IntegrityVerificationError if signature is invalid
    or does not match the vendor public key.
    """
    feed_file = Path(feed_path)
    sig_file = Path(signature_path)
    pub_file = Path(public_key_path)

    if not feed_file.is_file():
        raise FileNotFoundError(f"Threat feed file not found: {feed_file}")
    if not sig_file.is_file():
        raise FileNotFoundError(f"Detached signature file not found: {sig_file}")
    if not pub_file.is_file():
        raise FileNotFoundError(f"Vendor public key file not found: {pub_file}")

    feed_data = feed_file.read_bytes()
    signature_data = sig_file.read_bytes()
    public_key = load_public_key(pub_file)

    # Perform Ed25519 signature verification
    is_valid = verify_feed_signature(public_key, feed_data, signature_data)
    if not is_valid:
        logger.error("[-] Cryptographic Verification Failed: Feed signature invalid.")
        raise IntegrityVerificationError(
            "Cryptographic Verification Failed: Feed signature invalid or feed altered."
        )

    logger.info("[+] Threat feed verified via Ed25519.")

    try:
        payload = json.loads(feed_data.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise FeedSchemaError(f"Threat feed JSON parsing failed: {exc}") from exc

    return validate_feed_schema(payload)


def sign_feed_file(
    feed_path: Union[str, Path],
    private_key_path: Union[str, Path],
    output_signature_path: Optional[Union[str, Path]] = None,
) -> Path:
    """Signs a threat feed file using vendor private key and writes detached signature."""
    feed_file = Path(feed_path)
    priv_file = Path(private_key_path)

    if not feed_file.is_file():
        raise FileNotFoundError(f"Threat feed file not found: {feed_file}")
    if not priv_file.is_file():
        raise FileNotFoundError(f"Vendor private key file not found: {priv_file}")

    feed_data = feed_file.read_bytes()
    private_key = load_private_key(priv_file)
    signature = sign_feed_data(private_key, feed_data)

    out_path = Path(output_signature_path) if output_signature_path else feed_file.with_suffix(feed_file.suffix + ".sig")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(signature)
    return out_path


def main() -> int:
    """CLI utility for threat feed ingestion and integrity verification."""
    import argparse

    parser = argparse.ArgumentParser(
        description="PMFA Threat Feed Ingestion & Cryptographic Verification Module"
    )
    parser.add_argument(
        "--feed",
        default="pmfa/feeds/iocs.json",
        help="Path to threat feed JSON file (default: pmfa/feeds/iocs.json)",
    )
    parser.add_argument(
        "--sig",
        default="pmfa/feeds/iocs.json.sig",
        help="Path to detached signature file (default: pmfa/feeds/iocs.json.sig)",
    )
    parser.add_argument(
        "--pubkey",
        default="pmfa/keys/vendor_public.pem",
        help="Path to vendor public key PEM (default: pmfa/keys/vendor_public.pem)",
    )
    parser.add_argument(
        "--tamper",
        action="store_true",
        help="Simulate adversary tampering by modifying 1 byte of the feed before verification",
    )
    parser.add_argument(
        "--sign-with",
        metavar="PRIVATE_KEY_PATH",
        help="Sign the feed with specified private key and output detached .sig file",
    )

    args = parser.parse_args()

    # Analyst/Vendor signing mode
    if args.sign_with:
        try:
            sig_out = sign_feed_file(args.feed, args.sign_with, args.sig)
            print(f"[+] Detached signature generated successfully: {sig_out}")
            return 0
        except Exception as exc:
            sys.stderr.write(f"[-] Signing failed: {exc}\n")
            return 1

    # Tamper simulation mode (for live demonstration)
    if args.tamper:
        print("[*] Running Feed Tamper Check Demo (Simulating adversary tampering)...")
        try:
            feed_file = Path(args.feed)
            data = bytearray(feed_file.read_bytes())
            # Flip one byte
            data[0] = ord(b"X") if data[0] != ord(b"X") else ord(b"Y")
            pub_key = load_public_key(args.pubkey)
            sig_data = Path(args.sig).read_bytes()

            if not verify_feed_signature(pub_key, bytes(data), sig_data):
                sys.stderr.write("[-] Cryptographic Verification Failed: Feed signature invalid.\n")
                return E_INTEGRITY_FAIL
            else:
                print("[-] UNEXPECTED: Tampered feed passed verification!")
                return 1
        except Exception as exc:
            sys.stderr.write(f"[-] Verification aborted with error: {exc}\n")
            return 1

    # Standard feed ingestion & verification mode
    try:
        feed = verify_and_load_feed(args.feed, args.sig, args.pubkey)
        print(f"[+] Verified threat actor : {feed.threat_actor}")
        print(f"[+] Feed schema version   : {feed.version}")
        print(f"[+] Last updated          : {feed.last_updated}")
        print(f"[+] Indexed SHA-256 hashes: {len(feed.hashes_sha256)}")
        print(f"[+] Indexed paths         : {len(feed.suspicious_paths)}")
        print(f"[+] Indexed filenames     : {len(feed.suspicious_filenames)}")
        return 0
    except IntegrityVerificationError:
        return E_INTEGRITY_FAIL
    except Exception as exc:
        sys.stderr.write(f"[-] Feed ingestion error: {exc}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
