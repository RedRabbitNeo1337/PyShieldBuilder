from pathlib import Path


def save_private_key(path: Path, private_pem: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(private_pem)
    path.chmod(0o600)


def load_private_key(path: Path) -> bytes:
    return path.read_bytes()
