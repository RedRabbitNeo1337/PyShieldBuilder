import secrets


def secure_bytes(length: int) -> bytes:
    return secrets.token_bytes(length)
