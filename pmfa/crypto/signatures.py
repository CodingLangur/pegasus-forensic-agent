"""Digital signature generation and verification module supporting Ed25519 and RSA-PSS.

Provides cryptographic verification for threat intelligence feeds (iocs.json)
to prevent adversary poisoning or tampering with IoC definitions.
Supports:
- Ed25519 pure digital signatures (RFC 8032)
- RSA-PSS (2048/4096-bit with SHA-256 and PSS padding) per Design Doc Section 2.1 & 3
"""

from pathlib import Path
from typing import Tuple, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa

PublicKeyType = Union[ed25519.Ed25519PublicKey, rsa.RSAPublicKey]
PrivateKeyType = Union[ed25519.Ed25519PrivateKey, rsa.RSAPrivateKey]


def get_key_algorithm_name(key: Union[PublicKeyType, PrivateKeyType]) -> str:
    """Returns human-readable name of the asymmetric signature algorithm."""
    if isinstance(key, (ed25519.Ed25519PublicKey, ed25519.Ed25519PrivateKey)):
        return "Ed25519"
    if isinstance(key, (rsa.RSAPublicKey, rsa.RSAPrivateKey)):
        return "RSA-PSS"
    return "Unknown"


def verify_feed_signature(public_key: PublicKeyType, data: bytes, signature: bytes) -> bool:
    """Verifies that the threat feed has not been altered using Ed25519 or RSA-PSS."""
    try:
        if isinstance(public_key, ed25519.Ed25519PublicKey):
            public_key.verify(signature, data)
            return True
        elif isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            return True
        else:
            raise TypeError(f"Unsupported public key type: {type(public_key)}")
    except InvalidSignature:
        return False


def load_public_key(pem_source: Union[bytes, str, Path]) -> PublicKeyType:
    """Loads an Ed25519 or RSA public key from PEM bytes or file path."""
    if isinstance(pem_source, (str, Path)):
        pem_bytes = Path(pem_source).read_bytes()
    else:
        pem_bytes = pem_source

    loaded_key = serialization.load_pem_public_key(pem_bytes)
    if not isinstance(loaded_key, (ed25519.Ed25519PublicKey, rsa.RSAPublicKey)):
        raise TypeError(
            f"Loaded public key is neither Ed25519 nor RSA ({type(loaded_key).__name__})"
        )
    return loaded_key


def load_private_key(
    pem_source: Union[bytes, str, Path],
    password: Union[bytes, None] = None,
) -> PrivateKeyType:
    """Loads an Ed25519 or RSA private key from PEM bytes or file path."""
    if isinstance(pem_source, (str, Path)):
        pem_bytes = Path(pem_source).read_bytes()
    else:
        pem_bytes = pem_source

    loaded_key = serialization.load_pem_private_key(pem_bytes, password=password)
    if not isinstance(loaded_key, (ed25519.Ed25519PrivateKey, rsa.RSAPrivateKey)):
        raise TypeError(
            f"Loaded private key is neither Ed25519 nor RSA ({type(loaded_key).__name__})"
        )
    return loaded_key


def sign_feed_data(private_key: PrivateKeyType, data: bytes) -> bytes:
    """Generates an Ed25519 or RSA-PSS detached digital signature for given feed data."""
    if isinstance(private_key, ed25519.Ed25519PrivateKey):
        return private_key.sign(data)
    elif isinstance(private_key, rsa.RSAPrivateKey):
        return private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
    else:
        raise TypeError(f"Unsupported private key type: {type(private_key)}")


def generate_keypair(
    algorithm: str = "ed25519",
    rsa_bits: int = 2048,
) -> Tuple[PrivateKeyType, PublicKeyType]:
    """Generates a new asymmetric keypair (Ed25519 or RSA-2048/4096)."""
    algo = algorithm.lower().strip()
    if algo in {"rsa", "rsa-pss"}:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=rsa_bits,
        )
        public_key = private_key.public_key()
        return private_key, public_key
    elif algo in {"ed25519", "ed_25519"}:
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key, public_key
    else:
        raise ValueError(f"Unsupported algorithm '{algorithm}'. Choose 'ed25519' or 'rsa'.")


def serialize_public_key(public_key: PublicKeyType) -> bytes:
    """Serializes an Ed25519 or RSA public key to SubjectPublicKeyInfo PEM format."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def serialize_private_key(
    private_key: PrivateKeyType,
    encryption_algorithm: serialization.KeySerializationEncryption = serialization.NoEncryption(),
) -> bytes:
    """Serializes an Ed25519 or RSA private key to PKCS#8 PEM format."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algorithm,
    )
