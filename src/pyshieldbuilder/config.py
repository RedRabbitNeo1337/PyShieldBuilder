"""Configuration loading for builder settings."""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any
import tomllib

from .models import TransformationConfig


@dataclass(slots=True, frozen=True)
class BuilderConfig:
    """Build settings loaded from pyproject-like files."""

    source_dir: str
    entrypoint: str
    output_path: str = "dist/package.psb"
    package_version: str = "1.0.0"
    metadata_version: int = 1
    reproducible: bool = False
    sign_package: bool = True
    transformation: TransformationConfig = TransformationConfig()

    @classmethod
    def from_file(cls, path: str | Path) -> "BuilderConfig":
        data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
        config = data.get("tool", {}).get("pyshieldbuilder", {})
        transform_config = config.get("transform", {})
        return cls(
            source_dir=config["source_dir"],
            entrypoint=config["entrypoint"],
            output_path=config.get("output_path", "dist/package.psb"),
            package_version=config.get("package_version", "1.0.0"),
            metadata_version=int(config.get("metadata_version", 1)),
            reproducible=bool(config.get("reproducible", False)),
            sign_package=bool(config.get("sign_package", True)),
            transformation=_transformation_from_mapping(transform_config),
        )

    def with_overrides(self, **changes: Any) -> "BuilderConfig":
        """Return a copy with selected fields replaced."""
        return replace(self, **changes)


def _transformation_from_mapping(mapping: dict[str, Any]) -> TransformationConfig:
    return TransformationConfig(
        rename_identifiers=bool(mapping.get("rename_identifiers", False)),
        encrypt_strings=bool(mapping.get("encrypt_strings", False)),
        hide_constants=bool(mapping.get("hide_constants", False)),
        insert_dead_code=bool(mapping.get("insert_dead_code", False)),
        flatten_control_flow=bool(mapping.get("flatten_control_flow", False)),
        rewrite_imports=bool(mapping.get("rewrite_imports", False)),
    )
