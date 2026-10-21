"""AES-256-GCM Authenticated Encryption & Decryption Module.

Provides cryptographic confidentiality, integrity, and non-repudiation for forensic
evidence reports adhering to Section 2.4 and Section 6.3 of the design specification.

AEAD Structure: Nonce (12 bytes / 96 bits) || Ciphertext || Authentication Tag (16 bytes / 128 bits)
"""

import os
from pathlib import Path
from typing import Optional, Union

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# AES-256 requires a 256-bit (32-byte) key
AES_KEY_SIZE_BYTES = 32
# GCM standard nonce size is 96 bits (12 bytes)
GCM_NONCE_SIZE_BYTES = 12
# GCM standard authentication tag size is 128 bits (16 bytes)
GCM_TAG_SIZE_BYTES = 16


class EvidenceTamperingError(Exception):
    """Raised when AEAD tag validation fails, indicating evidence tampering."""
    pass


def generate_aes_key() -> bytes:
    """Generates a cryptographically secure 256-bit symmetric key using CSPRNG."""
    return AESGCM.generate_key(bit_length=256)


def encrypt_report(
    plaintext_json: bytes,
    key: bytes,
    associated_data: Optional[bytes] = None,
) -> bytes:
    """Encrypts plaintext report using AES-256-GCM.

    Structure: Nonce (12 bytes) || Ciphertext + Tag (16 bytes)
    Appends 128-bit authentication tag to ensure chain of custody integrity.
    """
    if len(key) != AES_KEY_SIZE_BYTES:
        raise ValueError(f"AES-256 key must be exactly {AES_KEY_SIZE_BYTES} bytes, got {len(key)}")

    aesgcm = AESGCM(key)
    nonce = os.urandom(GCM_NONCE_SIZE_BYTES)
    ciphertext = aesgcm.encrypt(nonce, plaintext_json, associated_data)
    return nonce + ciphertext


def decrypt_report(
    payload: bytes,
    key: bytes,
    associated_data: Optional[bytes] = None,
) -> bytes:
    """Decrypts ciphertext payload using AES-256-GCM and validates AEAD tag.

    Extracts the 12-byte nonce from header and authenticates tag before decryption.
    Raises EvidenceTamperingError if tag validation fails.
    """
    if len(key) != AES_KEY_SIZE_BYTES:
        raise ValueError(f"AES-256 key must be exactly {AES_KEY_SIZE_BYTES} bytes, got {len(key)}")

    if len(payload) < (GCM_NONCE_SIZE_BYTES + GCM_TAG_SIZE_BYTES):
        raise ValueError("Encrypted payload is too short to contain nonce and authentication tag")

    aesgcm = AESGCM(key)
    nonce = payload[:GCM_NONCE_SIZE_BYTES]
    ciphertext = payload[GCM_NONCE_SIZE_BYTES:]

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)
        return plaintext
    except InvalidTag as exc:
        raise EvidenceTamperingError(
            "Cryptographic integrity check failed: AEAD authentication tag mismatch. "
            "Evidence payload has been tampered with or corrupted."
        ) from exc


def save_key(key: bytes, key_path: Union[str, Path], as_hex: bool = True) -> Path:
    """Saves symmetric key to disk in hex or raw binary format."""
    path = Path(key_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if as_hex:
        path.write_text(key.hex(), encoding="utf-8")
    else:
        path.write_bytes(key)
    return path


def load_key(key_path: Union[str, Path]) -> bytes:
    """Loads symmetric key from disk, automatically parsing hex or raw bytes."""
    path = Path(key_path)
    if not path.is_file():
        raise FileNotFoundError(f"Key file not found: {path}")

    raw = path.read_bytes()
    # Check if key is hex-encoded string (64 hex characters)
    stripped = raw.strip()
    if len(stripped) == 64:
        try:
            return bytes.fromhex(stripped.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            pass

    if len(raw) == AES_KEY_SIZE_BYTES:
        return raw

    raise ValueError(f"Invalid key file format in {path}. Expected 32 raw bytes or 64 hex characters.")
