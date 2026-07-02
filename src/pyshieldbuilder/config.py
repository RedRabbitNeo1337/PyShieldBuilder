"""Configuration loading for builder settings."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import tomllib


@dataclass(slots=True, frozen=True)
class BuilderConfig:
    """Build settings loaded from pyproject-like files."""

    source_dir: str
    entrypoint: str
    output_path: str

    @classmethod
    def from_file(cls, path: str | Path) -> "BuilderConfig":
        data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
        config = data["tool"]["pyshieldbuilder"]
        return cls(
            source_dir=config["source_dir"],
            entrypoint=config["entrypoint"],
            output_path=config["output_path"],
        )
