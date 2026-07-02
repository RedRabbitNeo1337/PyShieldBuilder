from pyshieldbuilder.crypto import decrypt_bytes, encrypt_bytes
from pyshieldbuilder.exceptions import DecryptionError


def test_encrypt_decrypt_roundtrip() -> None:
    plaintext = b"secret payload"
    salt, nonce, ciphertext = encrypt_bytes(plaintext, "pw123")
    restored = decrypt_bytes(ciphertext, "pw123", salt, nonce)
    assert restored == plaintext


def test_decrypt_wrong_password_fails() -> None:
    salt, nonce, ciphertext = encrypt_bytes(b"payload", "correct")
    try:
        decrypt_bytes(ciphertext, "wrong", salt, nonce)
    except DecryptionError:
        return
    raise AssertionError("expected DecryptionError")
