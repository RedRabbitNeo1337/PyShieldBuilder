from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class BuilderConfig:
    source_dir: Path
    entry_module: str
    output_file: Path
    signing_alg: str = "ed25519"
    key_dir: Path | None = None
    compression_level: int = 9
