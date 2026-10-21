"""Ed25519 digital signature generation and verification module.

Provides cryptographic verification for threat intelligence feeds (iocs.json)
to prevent adversary poisoning or tampering with IoC definitions.
"""

from pathlib import Path
from typing import Union
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


def verify_feed_signature(public_key: ed25519.Ed25519PublicKey, data: bytes, signature: bytes) -> bool:
    """Verifies that the threat feed has not been altered."""
    try:
        public_key.verify(signature, data)
        return True
    except InvalidSignature:
        return False


def load_public_key(pem_source: Union[bytes, str, Path]) -> ed25519.Ed25519PublicKey:
    """Loads an Ed25519 public key from PEM bytes or file path."""
    if isinstance(pem_source, (str, Path)):
        pem_bytes = Path(pem_source).read_bytes()
    else:
        pem_bytes = pem_source

    loaded_key = serialization.load_pem_public_key(pem_bytes)
    if not isinstance(loaded_key, ed25519.Ed25519PublicKey):
        raise TypeError("Loaded public key is not an Ed25519 public key")
    return loaded_key


def load_private_key(
    pem_source: Union[bytes, str, Path],
    password: Union[bytes, None] = None,
) -> ed25519.Ed25519PrivateKey:
    """Loads an Ed25519 private key from PEM bytes or file path."""
    if isinstance(pem_source, (str, Path)):
        pem_bytes = Path(pem_source).read_bytes()
    else:
        pem_bytes = pem_source

    loaded_key = serialization.load_pem_private_key(pem_bytes, password=password)
    if not isinstance(loaded_key, ed25519.Ed25519PrivateKey):
        raise TypeError("Loaded private key is not an Ed25519 private key")
    return loaded_key


def sign_feed_data(private_key: ed25519.Ed25519PrivateKey, data: bytes) -> bytes:
    """Generates an Ed25519 detached digital signature for given feed data."""
    return private_key.sign(data)


def generate_keypair() -> tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    """Generates a new Ed25519 keypair."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_public_key(public_key: ed25519.Ed25519PublicKey) -> bytes:
    """Serializes an Ed25519 public key to PEM format."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def serialize_private_key(
    private_key: ed25519.Ed25519PrivateKey,
    encryption_algorithm: serialization.KeySerializationEncryption = serialization.NoEncryption(),
) -> bytes:
    """Serializes an Ed25519 private key to PKCS#8 PEM format."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algorithm,
    )
