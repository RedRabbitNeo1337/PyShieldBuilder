"""Package builder implementation."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .crypto import decrypt_bytes, encrypt_bytes
from .exceptions import InvalidPackageError, PackageBuildError
from .integrity import hash_bytes, verify_digest
from .models import DecryptedPayload, PackageMetadata
from .package import create_source_archive
from .protection import STAGE1_METHOD

_FORMAT_VERSION = 1


@dataclass(slots=True)
class PyShieldBuilder:
    """High-level builder for encrypted source packages."""

    source_dir: str | Path
    entrypoint: str

    def build(self, output_path: str | Path, password: str) -> Path:
        """Build and write an encrypted package."""
        return build_package(self.source_dir, output_path, password, self.entrypoint)


def build_package(
    source_dir: str | Path,
    output_path: str | Path,
    password: str,
    entrypoint: str,
) -> Path:
    """Build an encrypted package file from source files."""
    if not password:
        raise PackageBuildError("password must not be empty")

    archive = create_source_archive(source_dir)
    if not archive:
        raise PackageBuildError("no source files were collected")

    payload_sha256 = hash_bytes(archive)
    metadata = {
        "format_version": _FORMAT_VERSION,
        "created_at": datetime.now(UTC).isoformat(),
        "entrypoint": entrypoint,
        "file_count": sum(1 for _ in Path(source_dir).rglob("*.py")),
        "payload_sha256": payload_sha256,
        "stage1_enabled": True,
        "source_protection": STAGE1_METHOD,
    }

    aad = json.dumps(metadata, sort_keys=True).encode("utf-8")
    salt, nonce, ciphertext = encrypt_bytes(archive, password, aad=aad)

    envelope = {
        "metadata": metadata,
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }

    target = Path(output_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(envelope, indent=2), encoding="utf-8")
    return target


def load_and_decrypt(package_path: str | Path, password: str) -> DecryptedPayload:
    """Load package from disk and decrypt its payload."""
    try:
        envelope = json.loads(Path(package_path).read_text(encoding="utf-8"))
        metadata = envelope["metadata"]
        aad = json.dumps(metadata, sort_keys=True).encode("utf-8")
        archive = decrypt_bytes(
            base64.b64decode(envelope["ciphertext"]),
            password,
            base64.b64decode(envelope["salt"]),
            base64.b64decode(envelope["nonce"]),
            aad=aad,
        )
    except Exception as exc:
        raise InvalidPackageError("invalid package envelope") from exc

    if not verify_digest(archive, metadata["payload_sha256"]):
        raise InvalidPackageError("payload integrity verification failed")

    package_meta = PackageMetadata(
        format_version=metadata["format_version"],
        created_at=metadata["created_at"],
        entrypoint=metadata["entrypoint"],
        file_count=metadata["file_count"],
        payload_sha256=metadata["payload_sha256"],
        stage1_enabled=metadata.get("stage1_enabled", False),
        source_protection=metadata.get("source_protection"),
    )
    return DecryptedPayload(metadata=package_meta, archive_bytes=archive)
