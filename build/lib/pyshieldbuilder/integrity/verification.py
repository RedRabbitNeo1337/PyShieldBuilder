from .hashing import sha256_hex


def verify_hash(payload: bytes, expected_hex: str) -> bool:
    return sha256_hex(payload) == expected_hex
