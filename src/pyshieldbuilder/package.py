"""Archive creation and extraction for source payloads."""

from __future__ import annotations

import io
from pathlib import Path
import tarfile
from typing import Mapping


_TAR_MTIME = 1_700_000_000


def collect_source_files(source_dir: str | Path) -> dict[str, str]:
    """Collect Python source files from *source_dir* into a path-to-source mapping."""
    root = Path(source_dir)
    if not root.exists() or not root.is_dir():
        raise FileNotFoundError(f"source directory not found: {root}")
    files: dict[str, str] = {}
    for file_path in sorted(root.rglob("*.py")):
        if "__pycache__" in file_path.parts:
            continue
        files[file_path.relative_to(root).as_posix()] = file_path.read_text(encoding="utf-8")
    return files


def create_source_archive(source_dir: str | Path) -> bytes:
    """Create a deterministic tar.gz archive containing Python files from *source_dir*."""
    return create_source_archive_from_mapping(collect_source_files(source_dir))


def create_source_archive_from_mapping(source_map: Mapping[str, str]) -> bytes:
    """Create a deterministic tar.gz archive from a mapping of relative paths to source code."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz", format=tarfile.PAX_FORMAT) as tf:
        for relative_path in sorted(source_map):
            data = source_map[relative_path].encode("utf-8")
            info = tarfile.TarInfo(name=relative_path)
            info.size = len(data)
            info.mtime = _TAR_MTIME
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            info.mode = 0o644
            tf.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def extract_source_archive(archive_bytes: bytes) -> dict[str, str]:
    """Extract a tar.gz source archive into an in-memory mapping."""
    source_map: dict[str, str] = {}
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as tf:
        for member in tf.getmembers():
            if not member.isfile() or not member.name.endswith(".py"):
                continue
            handle = tf.extractfile(member)
            if handle is None:
                continue
            source_map[member.name] = handle.read().decode("utf-8")
    return source_map


def extract_source_archive_to_directory(archive_bytes: bytes, destination: str | Path) -> list[Path]:
    """Extract a source archive to *destination* and return the written files."""
    root = Path(destination)
    root.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for relative_path, contents in extract_source_archive(archive_bytes).items():
        target = root / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(contents, encoding="utf-8")
        written.append(target)
    return written
