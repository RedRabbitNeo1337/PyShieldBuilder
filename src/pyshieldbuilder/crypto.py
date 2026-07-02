"""Cryptographic primitives for payload encryption and decryption."""

from __future__ import annotations

import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .exceptions import DecryptionError

_KEY_SIZE = 32
_SALT_SIZE = 16
_NONCE_SIZE = 12
_PBKDF2_ITERATIONS = 390000


def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=_KEY_SIZE,
        salt=salt,
        iterations=_PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_bytes(plaintext: bytes, password: str, *, aad: bytes = b"") -> tuple[bytes, bytes, bytes]:
    """Encrypt bytes using AES-256-GCM and return (salt, nonce, ciphertext)."""
    salt = os.urandom(_SALT_SIZE)
    nonce = os.urandom(_NONCE_SIZE)
    key = _derive_key(password, salt)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    return salt, nonce, ciphertext


def decrypt_bytes(
    ciphertext: bytes,
    password: str,
    salt: bytes,
    nonce: bytes,
    *,
    aad: bytes = b"",
) -> bytes:
    """Decrypt bytes encrypted by :func:`encrypt_bytes`."""
    try:
        key = _derive_key(password, salt)
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except Exception as exc:  # pragma: no cover - cryptography internals vary
        raise DecryptionError("failed to decrypt payload") from exc
