"""Integrity helpers for hashing and verification."""

from __future__ import annotations

import hashlib
import hmac
from pathlib import Path


_HASH_ALGO = "sha256"


def hash_bytes(data: bytes) -> str:
    """Return SHA-256 digest for bytes."""
    return hashlib.sha256(data).hexdigest()


def hash_file(path: str | Path) -> str:
    """Return SHA-256 digest for file content."""
    hasher = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(8192), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def verify_digest(data: bytes, expected_digest: str) -> bool:
    """Constant-time digest verification."""
    return hmac.compare_digest(hash_bytes(data), expected_digest)
