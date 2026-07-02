from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_bytes(key: bytes, nonce: bytes, payload: bytes, aad: bytes = b"") -> bytes:
    return AESGCM(key).encrypt(nonce, payload, aad)


def decrypt_bytes(key: bytes, nonce: bytes, payload: bytes, aad: bytes = b"") -> bytes:
    return AESGCM(key).decrypt(nonce, payload, aad)
