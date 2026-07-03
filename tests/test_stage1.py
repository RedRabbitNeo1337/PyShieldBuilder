"""Tests for Stage 1 source-protection pipeline and verify CLI command."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from pyshieldbuilder.builder import PyShieldBuilder, build_package
from pyshieldbuilder.cli import main
from pyshieldbuilder.exceptions import InvalidPackageError
from pyshieldbuilder.runtime import inspect_package, execute_package
from pyshieldbuilder.stage1 import _PPLN, _PV, _RV, protect_archive, unprotect_archive


# ---------------------------------------------------------------------------
# Stage 1 protect/unprotect unit tests
# ---------------------------------------------------------------------------

def test_roundtrip_small() -> None:
    """protect_archive then unprotect_archive recovers the exact original bytes."""
    data = b"hello stage-1"
    env = protect_archive(data, _seed=42)
    assert unprotect_archive(env) == data


def test_roundtrip_large() -> None:
    """Roundtrip works for larger payloads (many chunks)."""
    data = b"x" * 10_000
    env = protect_archive(data, _seed=7)
    assert unprotect_archive(env) == data


def test_chunks_are_shuffled() -> None:
    """Chunks are not stored in original order (probabilistic, fixed seed)."""
    data = b"A" * 4096
    env = protect_archive(data, _seed=1)
    # The chunk map should not be the identity permutation for a non-trivial payload.
    chunk_map: list[int] = env["m"]
    assert chunk_map != list(range(len(chunk_map))), (
        "chunk map should not be the identity permutation for a shuffled payload"
    )


def test_chunk_count_range() -> None:
    """protect_archive produces between 1 and 24 chunks for a typical payload."""
    data = b"sample" * 500
    env = protect_archive(data)
    assert 1 <= len(env["c"]) <= 24


def test_tampered_chunk_raises() -> None:
    """Modifying a chunk value causes unprotect_archive to raise InvalidPackageError."""
    data = b"important data"
    env = protect_archive(data, _seed=0)
    env["c"][0] = env["c"][0][::-1]  # corrupt first chunk
    with pytest.raises(InvalidPackageError):
        unprotect_archive(env)


def test_tampered_hash_raises() -> None:
    """Replacing the stored hash causes unprotect_archive to raise InvalidPackageError."""
    data = b"important data"
    env = protect_archive(data, _seed=0)
    env["h"] = "0" * 64  # wrong hash
    with pytest.raises(InvalidPackageError):
        unprotect_archive(env)


def test_missing_key_raises() -> None:
    """An incomplete envelope raises InvalidPackageError."""
    with pytest.raises(InvalidPackageError):
        unprotect_archive({"c": [], "m": []})  # missing "h"


def test_map_length_mismatch_raises() -> None:
    """Mismatched chunk/map lengths raise InvalidPackageError."""
    data = b"test"
    env = protect_archive(data, _seed=0)
    env["m"] = env["m"][:-1]  # truncate map
    with pytest.raises(InvalidPackageError):
        unprotect_archive(env)


# ---------------------------------------------------------------------------
# Integration: new metadata fields in built packages
# ---------------------------------------------------------------------------

def _make_app(base: Path) -> Path:
    app = base / "app"
    app.mkdir()
    (app / "__init__.py").write_text("", encoding="utf-8")
    (app / "main.py").write_text("def run():\n    return 'stage1-ok'\n", encoding="utf-8")
    return app


def test_metadata_fields(tmp_path: Path) -> None:
    """Built packages expose all new metadata fields."""
    _make_app(tmp_path)
    pkg = tmp_path / "pkg.psb"
    PyShieldBuilder(source_dir=tmp_path, entrypoint="app.main:run").build(pkg, "pw")

    meta = inspect_package(str(pkg), "pw")
    assert meta.stage1_enabled is True
    assert meta.source_protection is True
    assert meta.protection_version == _PV
    assert meta.protection_pipeline == _PPLN
    assert meta.runtime_version == _RV


def test_execute_stage1_package(tmp_path: Path) -> None:
    """A stage-1 protected package executes correctly."""
    _make_app(tmp_path)
    pkg = tmp_path / "pkg.psb"
    PyShieldBuilder(source_dir=tmp_path, entrypoint="app.main:run").build(pkg, "pw")

    result = execute_package(str(pkg), "pw")
    assert result == "stage1-ok"


# ---------------------------------------------------------------------------
# Backward-compatibility: old-format packages (no stage1)
# ---------------------------------------------------------------------------

def test_backward_compat_no_stage1(tmp_path: Path) -> None:
    """Packages without stage1 fields load successfully with safe defaults."""
    from pyshieldbuilder.builder import _FORMAT_VERSION
    import base64
    from pyshieldbuilder.crypto import encrypt_bytes
    from pyshieldbuilder.integrity import hash_bytes
    from pyshieldbuilder.package import create_source_archive

    # Build a legacy-style package (raw archive, no stage1 fields).
    app = tmp_path / "legacy_app"
    app.mkdir()
    (app / "main.py").write_text("def run():\n    return 'legacy'\n", encoding="utf-8")

    archive = create_source_archive(app)
    payload_sha256 = hash_bytes(archive)
    metadata = {
        "format_version": _FORMAT_VERSION,
        "created_at": "2024-01-01T00:00:00+00:00",
        "entrypoint": "main:run",
        "file_count": 1,
        "payload_sha256": payload_sha256,
        # deliberately omit stage1_enabled and other new fields
    }
    aad = json.dumps(metadata, sort_keys=True).encode("utf-8")
    salt, nonce, ct = encrypt_bytes(archive, "pw", aad=aad)
    envelope = {
        "metadata": metadata,
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ct).decode("ascii"),
    }
    pkg = tmp_path / "legacy.psb"
    pkg.write_text(json.dumps(envelope), encoding="utf-8")

    meta = inspect_package(str(pkg), "pw")
    assert meta.stage1_enabled is False
    assert meta.source_protection is False
    assert meta.protection_version == ""
    assert meta.protection_pipeline == ""
    assert meta.runtime_version == ""

    result = execute_package(str(pkg), "pw")
    assert result == "legacy"


# ---------------------------------------------------------------------------
# CLI verify command
# ---------------------------------------------------------------------------

def test_cli_verify_valid(tmp_path: Path, capsys) -> None:
    """verify command exits 0 and prints valid status for a good package."""
    _make_app(tmp_path)
    pkg = tmp_path / "pkg.psb"
    assert main(["build", "--source", str(tmp_path), "--entrypoint", "app.main:run",
                 "--output", str(pkg), "--password", "pw"]) == 0
    capsys.readouterr()  # discard build output

    rc = main(["verify", "--package", str(pkg), "--password", "pw"])
    out = capsys.readouterr().out
    assert rc == 0
    data = json.loads(out)
    assert data["status"] == "valid"
    assert data["stage1_verified"] is True


def test_cli_verify_wrong_password(tmp_path: Path, capsys) -> None:
    """verify command exits 1 for wrong password."""
    _make_app(tmp_path)
    pkg = tmp_path / "pkg.psb"
    assert main(["build", "--source", str(tmp_path), "--entrypoint", "app.main:run",
                 "--output", str(pkg), "--password", "correct"]) == 0
    capsys.readouterr()

    rc = main(["verify", "--package", str(pkg), "--password", "wrong"])
    out = capsys.readouterr().out
    assert rc == 1
    data = json.loads(out)
    assert data["status"] == "invalid"


def test_cli_verify_tampered_package(tmp_path: Path, capsys) -> None:
    """verify command exits 1 when the ciphertext has been tampered with."""
    _make_app(tmp_path)
    pkg = tmp_path / "pkg.psb"
    assert main(["build", "--source", str(tmp_path), "--entrypoint", "app.main:run",
                 "--output", str(pkg), "--password", "pw"]) == 0
    capsys.readouterr()

    # Flip a byte in the ciphertext to simulate tampering.
    envelope = json.loads(pkg.read_text())
    ct_bytes = bytearray(base64.b64decode(envelope["ciphertext"]))
    ct_bytes[0] ^= 0xFF
    envelope["ciphertext"] = base64.b64encode(bytes(ct_bytes)).decode("ascii")
    pkg.write_text(json.dumps(envelope))

    rc = main(["verify", "--package", str(pkg), "--password", "pw"])
    out = capsys.readouterr().out
    assert rc == 1
    data = json.loads(out)
    assert data["status"] == "invalid"
