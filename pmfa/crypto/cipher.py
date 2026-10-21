"""AES-256-GCM Authenticated Encryption & Decryption Module with Key Wrapping.

Provides cryptographic confidentiality, integrity, non-repudiation, and key encapsulation
for forensic evidence reports adhering to Section 2.4 and Section 6.3 of the design specification.

AEAD Structure: Nonce (12 bytes / 96 bits) || Ciphertext || Authentication Tag (16 bytes / 128 bits)

Key Wrapping Options:
1. RSA-OAEP (SHA-256) asymmetric key wrapping for analyst public keys
2. PBKDF2-HMAC-SHA256 (100k rounds) + AES-256-GCM passphrase key wrapping
3. Ephemeral plaintext key storage (for demo and automated test pipelines)
"""

import base64
import json
import os
from pathlib import Path
from typing import Optional, Tuple, Union

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# AES-256 requires a 256-bit (32-byte) key
AES_KEY_SIZE_BYTES = 32
# GCM standard nonce size is 96 bits (12 bytes)
GCM_NONCE_SIZE_BYTES = 12
# GCM standard authentication tag size is 128 bits (16 bytes)
GCM_TAG_SIZE_BYTES = 16
# Salt size for password-derived key wrapping
SALT_SIZE_BYTES = 16
PBKDF2_ITERATIONS = 100_000

WRAPPED_KEY_HEADER = "-----BEGIN PMFA WRAPPED KEY-----"
WRAPPED_KEY_FOOTER = "-----END PMFA WRAPPED KEY-----"


class EvidenceTamperingError(Exception):
    """Raised when AEAD tag validation fails, indicating evidence tampering."""
    pass


class KeyWrappingError(Exception):
    """Raised when key wrapping or unwrapping operations fail."""
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


# =====================================================================
# Key Wrapping: RSA-OAEP (Analyst Public Key)
# =====================================================================

def wrap_key_rsa(aes_key: bytes, analyst_public_key: rsa.RSAPublicKey) -> bytes:
    """Wraps (encrypts) the ephemeral AES-256 key using an analyst's RSA public key with OAEP (SHA-256)."""
    if len(aes_key) != AES_KEY_SIZE_BYTES:
        raise ValueError(f"AES-256 key must be {AES_KEY_SIZE_BYTES} bytes, got {len(aes_key)}")

    try:
        wrapped = analyst_public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return wrapped
    except Exception as exc:
        raise KeyWrappingError(f"RSA-OAEP key wrapping failed: {exc}") from exc


def unwrap_key_rsa(wrapped_key: bytes, analyst_private_key: rsa.RSAPrivateKey) -> bytes:
    """Unwraps (decrypts) the ephemeral AES-256 key using the analyst's RSA private key."""
    try:
        unwrapped = analyst_private_key.decrypt(
            wrapped_key,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        if len(unwrapped) != AES_KEY_SIZE_BYTES:
            raise KeyWrappingError(f"Unwrapped key length mismatch: {len(unwrapped)} bytes")
        return unwrapped
    except Exception as exc:
        raise KeyWrappingError(f"RSA-OAEP key unwrapping failed: {exc}") from exc


def load_analyst_public_key(pem_source: Union[bytes, str, Path]) -> rsa.RSAPublicKey:
    """Loads an analyst's RSA public key from PEM file or bytes."""
    if isinstance(pem_source, (str, Path)):
        pem_bytes = Path(pem_source).read_bytes()
    else:
        pem_bytes = pem_source

    loaded = serialization.load_pem_public_key(pem_bytes)
    if not isinstance(loaded, rsa.RSAPublicKey):
        raise TypeError(f"Loaded key is not an RSA public key ({type(loaded).__name__})")
    return loaded


def load_analyst_private_key(
    pem_source: Union[bytes, str, Path],
    password: Optional[bytes] = None,
) -> rsa.RSAPrivateKey:
    """Loads an analyst's RSA private key from PEM file or bytes."""
    if isinstance(pem_source, (str, Path)):
        pem_bytes = Path(pem_source).read_bytes()
    else:
        pem_bytes = pem_source

    loaded = serialization.load_pem_private_key(pem_bytes, password=password)
    if not isinstance(loaded, rsa.RSAPrivateKey):
        raise TypeError(f"Loaded key is not an RSA private key ({type(loaded).__name__})")
    return loaded


def generate_analyst_keypair(key_size: int = 2048) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Generates an analyst RSA keypair for evidence key wrapping."""
    priv = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    pub = priv.public_key()
    return priv, pub


# =====================================================================
# Key Wrapping: Passphrase (PBKDF2 + AES-256-GCM)
# =====================================================================

def wrap_key_passphrase(
    aes_key: bytes,
    passphrase: str,
    iterations: int = PBKDF2_ITERATIONS,
) -> bytes:
    """Wraps the ephemeral AES-256 key using a passphrase-derived Key Encryption Key (KEK).

    Output format: Salt (16 bytes) || Nonce (12 bytes) || Ciphertext + Tag (32 + 16 bytes)
    """
    if len(aes_key) != AES_KEY_SIZE_BYTES:
        raise ValueError(f"AES-256 key must be {AES_KEY_SIZE_BYTES} bytes, got {len(aes_key)}")
    if not passphrase:
        raise ValueError("Passphrase cannot be empty")

    salt = os.urandom(SALT_SIZE_BYTES)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE_BYTES,
        salt=salt,
        iterations=iterations,
    )
    kek = kdf.derive(passphrase.encode("utf-8"))

    aesgcm = AESGCM(kek)
    nonce = os.urandom(GCM_NONCE_SIZE_BYTES)
    ciphertext = aesgcm.encrypt(nonce, aes_key, b"PMFA-KEY-WRAP")
    return salt + nonce + ciphertext


def unwrap_key_passphrase(
    wrapped_payload: bytes,
    passphrase: str,
    iterations: int = PBKDF2_ITERATIONS,
) -> bytes:
    """Unwraps the ephemeral AES-256 key using the provided passphrase."""
    min_len = SALT_SIZE_BYTES + GCM_NONCE_SIZE_BYTES + AES_KEY_SIZE_BYTES + GCM_TAG_SIZE_BYTES
    if len(wrapped_payload) < min_len:
        raise KeyWrappingError("Passphrase-wrapped payload is corrupted or truncated")

    salt = wrapped_payload[:SALT_SIZE_BYTES]
    nonce = wrapped_payload[SALT_SIZE_BYTES : SALT_SIZE_BYTES + GCM_NONCE_SIZE_BYTES]
    ciphertext = wrapped_payload[SALT_SIZE_BYTES + GCM_NONCE_SIZE_BYTES :]

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE_BYTES,
        salt=salt,
        iterations=iterations,
    )
    kek = kdf.derive(passphrase.encode("utf-8"))

    aesgcm = AESGCM(kek)
    try:
        unwrapped = aesgcm.decrypt(nonce, ciphertext, b"PMFA-KEY-WRAP")
        return unwrapped
    except InvalidTag as exc:
        raise KeyWrappingError("Invalid passphrase: Key unwrapping authentication failed.") from exc


# =====================================================================
# Key Storage & File Formatting
# =====================================================================

def save_key(
    key: bytes,
    key_path: Union[str, Path],
    as_hex: bool = True,
    wrapping_type: Optional[str] = None,
) -> Path:
    """Saves symmetric key (plaintext or wrapped) to disk with self-describing metadata."""
    path = Path(key_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    if wrapping_type:
        envelope = {
            "format": "PMFA_WRAPPED_KEY_v1",
            "wrapping_type": wrapping_type,
            "data_b64": base64.b64encode(key).decode("ascii"),
        }
        envelope_text = f"{WRAPPED_KEY_HEADER}\n{json.dumps(envelope, indent=2)}\n{WRAPPED_KEY_FOOTER}\n"
        path.write_text(envelope_text, encoding="utf-8")
    elif as_hex:
        path.write_text(key.hex(), encoding="utf-8")
    else:
        path.write_bytes(key)

    return path


def load_key(
    key_path: Union[str, Path],
    analyst_private_key: Optional[rsa.RSAPrivateKey] = None,
    passphrase: Optional[str] = None,
) -> bytes:
    """Loads and optionally unwraps symmetric key from disk.

    Automatically detects self-describing wrapped envelopes (RSA-OAEP or Passphrase)
    or standard plaintext 64-hex / 32-byte binary key files.
    """
    path = Path(key_path)
    if not path.is_file():
        raise FileNotFoundError(f"Key file not found: {path}")

    raw = path.read_bytes()
    text = None
    try:
        text = raw.decode("utf-8").strip()
    except UnicodeDecodeError:
        pass

    # Check for self-describing wrapped key envelope
    if text and WRAPPED_KEY_HEADER in text:
        try:
            json_str = text.split(WRAPPED_KEY_HEADER)[1].split(WRAPPED_KEY_FOOTER)[0].strip()
            envelope = json.loads(json_str)
            wrapped_bytes = base64.b64decode(envelope["data_b64"])
            wtype = envelope.get("wrapping_type", "RSA-OAEP")

            if wtype == "RSA-OAEP":
                if not analyst_private_key:
                    raise KeyWrappingError(
                        f"Key file {path.name} is wrapped with RSA-OAEP. Analyst private key required to unwrap."
                    )
                return unwrap_key_rsa(wrapped_bytes, analyst_private_key)

            elif wtype in {"PASSPHRASE", "PBKDF2-AES-GCM"}:
                if not passphrase:
                    raise KeyWrappingError(
                        f"Key file {path.name} is wrapped with a passphrase. Passphrase required to unwrap."
                    )
                return unwrap_key_passphrase(wrapped_bytes, passphrase)
            else:
                raise KeyWrappingError(f"Unknown key wrapping type: {wtype}")
        except KeyWrappingError:
            raise
        except Exception as exc:
            raise KeyWrappingError(f"Failed to parse wrapped key envelope in {path}: {exc}") from exc

    # If raw is hex-encoded 64 characters
    if text and len(text) == 64:
        try:
            return bytes.fromhex(text)
        except ValueError:
            pass

    # If raw is direct 32-byte binary key
    if len(raw) == AES_KEY_SIZE_BYTES:
        return raw

    raise ValueError(f"Invalid key file format in {path}. Expected 32 raw bytes, 64 hex characters, or wrapped key envelope.")
