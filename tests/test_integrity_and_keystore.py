from pathlib import Path

from pyshieldbuilder.crypto import load_private_key, save_private_key
from pyshieldbuilder.integrity import sha256_hex, verify_hash


def test_integrity_hash_roundtrip():
    payload = b"abc"
    digest = sha256_hex(payload)
    assert verify_hash(payload, digest)


def test_key_store_roundtrip(tmp_path: Path):
    path = tmp_path / "private.pem"
    key = b"key-material"
    save_private_key(path, key)
    assert load_private_key(path) == key
