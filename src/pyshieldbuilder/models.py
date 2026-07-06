"""Data models for package metadata and runtime payloads."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(slots=True, frozen=True)
class TransformationConfig:
    """Source transformation flags used during package build."""

    rename_identifiers: bool = False
    encrypt_strings: bool = False
    hide_constants: bool = False
    insert_dead_code: bool = False
    flatten_control_flow: bool = False
    rewrite_imports: bool = False


@dataclass(slots=True, frozen=True)
class PackageMetadata:
    """Metadata describing an encrypted package and its manifest."""

    metadata_version: int
    format_version: int
    package_version: str
    created_at: str
    entrypoint: str
    file_count: int
    payload_sha256: str
    manifest_sha256: str
    signature_sha256: str
    reproducible: bool
    transform_flags: dict[str, bool]
    source_hashes: dict[str, str]
    extra: dict[str, Any]


@dataclass(slots=True, frozen=True)
class DecryptedPayload:
    """Payload content recovered after decryption."""

    metadata: PackageMetadata
    archive_bytes: bytes
