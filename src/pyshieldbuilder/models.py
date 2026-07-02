"""Data models for package metadata and runtime payloads."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True, frozen=True)
class PackageMetadata:
    """Metadata describing an encrypted package."""

    format_version: int
    created_at: str
    entrypoint: str
    file_count: int
    payload_sha256: str
    stage1_enabled: bool = False
    source_protection: str | None = None


@dataclass(slots=True, frozen=True)
class DecryptedPayload:
    """Payload content recovered after decryption."""

    metadata: PackageMetadata
    archive_bytes: bytes
