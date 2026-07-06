"""Cryptographic primitives for payload encryption and decryption."""

from __future__ import annotations

import hashlib
import hmac
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .exceptions import DecryptionError

_KEY_SIZE = 32
_SALT_SIZE = 16
_NONCE_SIZE = 12
_PBKDF2_ITERATIONS = 390000


def _derive_key(password: str, salt: bytes, *, context: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=_KEY_SIZE,
        salt=salt + context,
        iterations=_PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def derive_encryption_key(password: str, salt: bytes) -> bytes:
    """Return the AES-GCM key derived from the given password."""
    return _derive_key(password, salt, context=b":enc")


def derive_signing_key(password: str, salt: bytes) -> bytes:
    """Return the signing key derived from the given password."""
    return _derive_key(password, salt, context=b":sig")


def encrypt_bytes(plaintext: bytes, password: str, *, aad: bytes = b"") -> tuple[bytes, bytes, bytes]:
    """Encrypt bytes using AES-256-GCM and return ``(salt, nonce, ciphertext)``."""
    salt = os.urandom(_SALT_SIZE)
    nonce = os.urandom(_NONCE_SIZE)
    key = derive_encryption_key(password, salt)
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
        key = derive_encryption_key(password, salt)
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except Exception as exc:  # pragma: no cover - cryptography internals vary
        raise DecryptionError("failed to decrypt payload") from exc


def sign_bytes(data: bytes, key: bytes) -> str:
    """Return a hex signature for *data* using ``key``."""
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def verify_signature(data: bytes, key: bytes, expected_signature: str) -> bool:
    """Validate a hex signature in constant time."""
    return hmac.compare_digest(sign_bytes(data, key), expected_signature)
