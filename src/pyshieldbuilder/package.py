"""Archive creation and extraction for source payloads."""

from __future__ import annotations

import io
import tarfile
from pathlib import Path


def create_source_archive(source_dir: str | Path) -> bytes:
    """Create a tar.gz archive containing Python files from *source_dir*."""
    root = Path(source_dir)
    if not root.exists() or not root.is_dir():
        raise FileNotFoundError(f"source directory not found: {root}")

    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tf:
        for file_path in sorted(root.rglob("*.py")):
            if "__pycache__" in file_path.parts:
                continue
            arcname = file_path.relative_to(root).as_posix()
            tf.add(file_path, arcname=arcname)
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
