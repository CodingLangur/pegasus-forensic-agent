"""Cryptographic hashing routines for PMFA.

Implements streaming SHA-256 block hashing for fingerprinting files,
device dumps, SQLite databases, and forensic artifacts with minimal memory overhead.
"""

import hashlib
from pathlib import Path
from typing import Union

# Default streaming buffer size: 64 KB (65,536 bytes) as specified in Design Doc Section 6.3
DEFAULT_CHUNK_SIZE = 65536


def compute_sha256(file_path: Union[str, Path], chunk_size: int = DEFAULT_CHUNK_SIZE) -> str:
    """Computes streaming SHA-256 digest of a target file.

    Reads in blocks of chunk_size to ensure constant low memory consumption
    even when processing multi-gigabyte device dumps or database files.
    """
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"File not found for SHA-256 computation: {path}")

    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            hasher.update(chunk)
    return hasher.hexdigest()


def compute_sha256_bytes(data: bytes) -> str:
    """Computes SHA-256 hex digest directly from in-memory bytes."""
    return hashlib.sha256(data).hexdigest()
