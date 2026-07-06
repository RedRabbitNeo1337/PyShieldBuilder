"""Package builder implementation."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
import platform
from typing import Any

from .config import BuilderConfig
from .crypto import decrypt_bytes, derive_signing_key, encrypt_bytes, sign_bytes, verify_signature
from .exceptions import InvalidPackageError, PackageBuildError
from .integrity import hash_bytes, verify_digest
from .models import DecryptedPayload, PackageMetadata, TransformationConfig
from .package import collect_source_files, create_source_archive_from_mapping
from .transform import transform_source

_FORMAT_VERSION = 2


@dataclass(slots=True)
class PyShieldBuilder:
    """High-level builder for encrypted source packages."""

    source_dir: str | Path
    entrypoint: str
    config: BuilderConfig | None = None

    def build(self, output_path: str | Path, password: str) -> Path:
        """Build and write an encrypted package."""
        options = self.config or BuilderConfig(source_dir=str(self.source_dir), entrypoint=self.entrypoint)
        return build_package(
            self.source_dir,
            output_path,
            password,
            self.entrypoint,
            transformation=options.transformation,
            reproducible=options.reproducible,
            sign_package=options.sign_package,
            package_version=options.package_version,
            metadata_version=options.metadata_version,
        )


def build_package(
    source_dir: str | Path,
    output_path: str | Path,
    password: str,
    entrypoint: str,
    *,
    transformation: TransformationConfig | None = None,
    reproducible: bool = False,
    sign_package: bool = True,
    package_version: str = "1.0.0",
    metadata_version: int = 1,
) -> Path:
    """Build an encrypted package file from source files."""
    if not password:
        raise PackageBuildError("password must not be empty")

    config = transformation or TransformationConfig()
    source_map = collect_source_files(source_dir)
    if not source_map:
        raise PackageBuildError("no source files were collected")

    transformed_map = _transform_source_map(source_map, config)
    archive = create_source_archive_from_mapping(transformed_map)
    payload_sha256 = hash_bytes(archive)
    manifest_body = _build_manifest(
        source_dir=Path(source_dir),
        entrypoint=entrypoint,
        file_count=len(source_map),
        payload_sha256=payload_sha256,
        source_hashes={path: hash_bytes(source.encode("utf-8")) for path, source in transformed_map.items()},
        transform_flags=config,
        reproducible=reproducible,
        package_version=package_version,
        metadata_version=metadata_version,
    )
    manifest_bytes = _canonical_json(manifest_body)
    salt, nonce, ciphertext = _encrypt_archive(archive, password, manifest_bytes, reproducible=reproducible)
    signature = sign_bytes(manifest_bytes, derive_signing_key(password, salt)) if sign_package else ""
    manifest_sha256 = hash_bytes(manifest_bytes)

    envelope = {
        "manifest": manifest_body,
        "manifest_sha256": manifest_sha256,
        "signature": signature,
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }

    target = Path(output_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(envelope, indent=2, sort_keys=True), encoding="utf-8")
    return target


def load_and_decrypt(package_path: str | Path, password: str) -> DecryptedPayload:
    """Load package from disk and decrypt its payload."""
    try:
        envelope = json.loads(Path(package_path).read_text(encoding="utf-8"))
        manifest, manifest_bytes = _load_manifest(envelope)
        salt = base64.b64decode(envelope["salt"])
        nonce = base64.b64decode(envelope["nonce"])
        ciphertext = base64.b64decode(envelope["ciphertext"])
        archive = decrypt_bytes(ciphertext, password, salt, nonce, aad=manifest_bytes)
        if envelope.get("signature"):
            if not verify_signature(manifest_bytes, derive_signing_key(password, salt), envelope["signature"]):
                raise InvalidPackageError("package signature verification failed")
        if envelope.get("manifest_sha256") and envelope["manifest_sha256"] != hash_bytes(manifest_bytes):
            raise InvalidPackageError("manifest integrity verification failed")
    except InvalidPackageError:
        raise
    except Exception as exc:
        raise InvalidPackageError("invalid package envelope") from exc

    if not verify_digest(archive, manifest["payload_sha256"]):
        raise InvalidPackageError("payload integrity verification failed")  # pragma: no cover

    package_meta = PackageMetadata(
        metadata_version=int(manifest.get("metadata_version", 1)),
        format_version=int(manifest.get("format_version", _FORMAT_VERSION)),
        package_version=str(manifest.get("package_version", "1.0.0")),
        created_at=str(manifest["created_at"]),
        entrypoint=str(manifest["entrypoint"]),
        file_count=int(manifest["file_count"]),
        payload_sha256=str(manifest["payload_sha256"]),
        manifest_sha256=hash_bytes(manifest_bytes),
        signature_sha256=str(envelope.get("signature", "")),
        reproducible=bool(manifest.get("reproducible", False)),
        transform_flags=dict(manifest.get("transform_flags", {})),
        source_hashes=dict(manifest.get("source_hashes", {})),
        extra=dict(manifest.get("extra", {})),
    )
    return DecryptedPayload(metadata=package_meta, archive_bytes=archive)


def _transform_source_map(source_map: dict[str, str], config: TransformationConfig) -> dict[str, str]:
    transformed: dict[str, str] = {}
    for relative_path, source in source_map.items():
        if config == TransformationConfig():
            transformed[relative_path] = source
            continue
        module_name = relative_path[:-3].replace("/", ".")
        artifact = transform_source(
            source,
            module_name=module_name,
            config=config,
            deterministic_key=_deterministic_transform_key(relative_path, source, config),
        )
        transformed[relative_path] = artifact.source
    return transformed


def _build_manifest(
    *,
    source_dir: Path,
    entrypoint: str,
    file_count: int,
    payload_sha256: str,
    source_hashes: dict[str, str],
    transform_flags: TransformationConfig,
    reproducible: bool,
    package_version: str,
    metadata_version: int,
) -> dict[str, Any]:
    created_at = datetime.fromtimestamp(0, UTC).isoformat() if reproducible else datetime.now(UTC).isoformat()
    return {
        "metadata_version": metadata_version,
        "format_version": _FORMAT_VERSION,
        "package_version": package_version,
        "created_at": created_at,
        "entrypoint": entrypoint,
        "file_count": file_count,
        "payload_sha256": payload_sha256,
        "reproducible": reproducible,
        "transform_flags": {
            "rename_identifiers": transform_flags.rename_identifiers,
            "encrypt_strings": transform_flags.encrypt_strings,
            "hide_constants": transform_flags.hide_constants,
            "insert_dead_code": transform_flags.insert_dead_code,
            "flatten_control_flow": transform_flags.flatten_control_flow,
            "rewrite_imports": transform_flags.rewrite_imports,
        },
        "source_hashes": source_hashes,
        "extra": {
            "source_dir": str(source_dir.resolve()),
            "python_version": platform.python_version(),
        },
    }


def _canonical_json(data: dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _encrypt_archive(
    archive: bytes,
    password: str,
    aad: bytes,
    *,
    reproducible: bool,
) -> tuple[bytes, bytes, bytes]:
    if reproducible:
        seed = hashlib.sha256(password.encode("utf-8") + aad + archive).digest()
        salt = seed[:16]
        nonce = seed[16:28]
        ciphertext = _encrypt_with_fixed_material(archive, password, salt, nonce, aad)
        return salt, nonce, ciphertext
    return encrypt_bytes(archive, password, aad=aad)


def _deterministic_transform_key(relative_path: str, source: str, config: TransformationConfig) -> str:
    digest = hashlib.sha256(
        (
            relative_path
            + "\n"
            + source
            + "\n"
            + json.dumps(
                {
                    "rename_identifiers": config.rename_identifiers,
                    "encrypt_strings": config.encrypt_strings,
                    "hide_constants": config.hide_constants,
                    "insert_dead_code": config.insert_dead_code,
                    "flatten_control_flow": config.flatten_control_flow,
                    "rewrite_imports": config.rewrite_imports,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        ).encode("utf-8")
    ).digest()
    return base64.b64encode(digest[:16]).decode("ascii")


def _encrypt_with_fixed_material(
    plaintext: bytes,
    password: str,
    salt: bytes,
    nonce: bytes,
    aad: bytes,
) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    key = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt + b":enc",
        iterations=390000,
    ).derive(password.encode("utf-8"))
    return AESGCM(key).encrypt(nonce, plaintext, aad)


def _load_manifest(envelope: dict[str, Any]) -> tuple[dict[str, Any], bytes]:
    manifest = envelope.get("manifest")
    if isinstance(manifest, dict):
        return manifest, _canonical_json(manifest)
    metadata = envelope.get("metadata")
    if isinstance(metadata, dict):
        return metadata, json.dumps(metadata, sort_keys=True).encode("utf-8")
    raise InvalidPackageError("invalid package manifest")
