from pyshieldbuilder.crypto import decrypt_bytes, encrypt_bytes


def test_aes_roundtrip():
    key = b"k" * 32
    nonce = b"n" * 12
    payload = b"payload"
    aad = b"meta"
    encrypted = encrypt_bytes(key, nonce, payload, aad)
    assert decrypt_bytes(key, nonce, encrypted, aad) == payload
