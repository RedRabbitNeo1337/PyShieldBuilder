"""Data models for package metadata and runtime payloads."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True, frozen=True)
class PackageMetadata:
    """Metadata describing an encrypted package."""

    format_version: int
    created_at: str
    entrypoint: str
    file_count: int
    payload_sha256: str
    # Stage 1 source-protection fields (absent in older packages – default False/"").
    stage1_enabled: bool = False
    source_protection: bool = False
    protection_version: str = ""
    protection_pipeline: str = ""
    runtime_version: str = ""


@dataclass(slots=True, frozen=True)
class DecryptedPayload:
    """Payload content recovered after decryption."""

    metadata: PackageMetadata
    archive_bytes: bytes
