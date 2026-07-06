from __future__ import annotations

import base64
import hashlib
import json
import io
import tarfile
from pathlib import Path

import pytest

from pyshieldbuilder.builder import PyShieldBuilder, build_package, load_and_decrypt
from pyshieldbuilder.config import BuilderConfig
from pyshieldbuilder.crypto import derive_signing_key, encrypt_bytes, sign_bytes
from pyshieldbuilder.exceptions import InvalidPackageError, PackageBuildError, RuntimeExecutionError
from pyshieldbuilder.models import TransformationConfig
from pyshieldbuilder.package import (
    collect_source_files,
    create_source_archive_from_mapping,
    create_source_archive,
    extract_source_archive,
    extract_source_archive_to_directory,
)
from pyshieldbuilder import runtime
from pyshieldbuilder.runtime import execute_package, extract_package, inspect_package, verify_package
from pyshieldbuilder.transform import _expand_nodes, transform_source


def _make_sample_app(base: Path) -> Path:
    app = base / "app"
    app.mkdir()
    (app / "__init__.py").write_text("", encoding="utf-8")
    (app / "helpers.py").write_text(
        "def message():\n    return 'ok'\n",
        encoding="utf-8",
    )
    (app / "main.py").write_text(
        "import math\n"
        "from app.helpers import message\n"
        "def run():\n"
        "    prefix = 'run'\n"
        "    number = 7\n"
        "    total = math.floor(math.sqrt(16))\n"
        "    return prefix + ':' + message() + ':' + str(number) + ':' + str(total)\n",
        encoding="utf-8",
    )
    return base


def test_transform_pipeline_round_trip() -> None:
    source = (
        "import math\n"
        "from math import sqrt\n"
        "def run():\n"
        "    text = 'hello'\n"
        "    value = 7\n"
        "    total = math.floor(sqrt(16))\n"
        "    return text + ':' + str(value) + ':' + str(total)\n"
    )
    artifact = transform_source(
        source,
        module_name="sample",
        config=TransformationConfig(
            rename_identifiers=True,
            encrypt_strings=True,
            hide_constants=True,
            insert_dead_code=True,
            flatten_control_flow=True,
            rewrite_imports=True,
        ),
    )
    assert "__psb_decode" in artifact.source
    assert "__psb_xor" in artifact.source
    assert "while True" in artifact.source

    namespace: dict[str, object] = {}
    exec(artifact.source, namespace)
    assert namespace["run"]() == "hello:7:4"


def test_transform_pipeline_async_edges() -> None:
    source = (
        "import os as operating_system\n"
        "async def run(*args, **kwargs):\n"
        "    import math as local_math\n"
        "    flag = True\n"
        "    nothing = None\n"
        "    try:\n"
        "        class Inner:\n"
        "            value = 1\n"
        "        async def nested_async(value):\n"
        "            return value\n"
        "        def nested(value):\n"
        "            return value\n"
        "        marker = nested('x')\n"
        "        raise ValueError('boom')\n"
        "    except ValueError:\n"
        "        return operating_system.name + ':' + marker + ':' + str(args) + ':' + str(kwargs) + ':' + str(flag) + ':' + str(nothing) + ':' + str(local_math.ceil(1))\n"
    )
    artifact = transform_source(
        source,
        module_name="async_sample",
        config=TransformationConfig(rename_identifiers=True, flatten_control_flow=True, rewrite_imports=True),
    )
    namespace: dict[str, object] = {}
    exec(artifact.source, namespace)

    import asyncio

    assert asyncio.run(namespace["run"](1, two=2)).endswith("True:None:1")


def test_collect_archive_and_extract(tmp_path: Path) -> None:
    app = _make_sample_app(tmp_path)
    sources = collect_source_files(app)
    archive = create_source_archive_from_mapping(sources)

    assert extract_source_archive(archive) == sources

    extracted = extract_source_archive_to_directory(archive, tmp_path / "out")
    assert {path.relative_to(tmp_path / "out").as_posix() for path in extracted} == set(sources)


def test_package_error_paths(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        collect_source_files(tmp_path / "missing")

    source_root = tmp_path / "source"
    source_root.mkdir()
    (source_root / "__pycache__").mkdir()
    (source_root / "__pycache__" / "ignored.py").write_text("ignored = True", encoding="utf-8")
    (source_root / "note.txt").write_text("note", encoding="utf-8")
    (source_root / "main.py").write_text("print('ok')", encoding="utf-8")

    sources = collect_source_files(source_root)
    assert sources == {"main.py": "print('ok')"}

    archive = create_source_archive(source_root)
    extracted = extract_source_archive(archive)
    assert extracted == {"main.py": "print('ok')"}

    assert _expand_nodes(None) == []

    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz", format=tarfile.PAX_FORMAT) as tf:
        dir_info = tarfile.TarInfo(name="nested/")
        dir_info.type = tarfile.DIRTYPE
        tf.addfile(dir_info)
        note = b"ignored"
        note_info = tarfile.TarInfo(name="nested/note.txt")
        note_info.size = len(note)
        tf.addfile(note_info, io.BytesIO(note))
        py_info = tarfile.TarInfo(name="nested/module.py")
        py_info.size = len(b"print('x')")
        tf.addfile(py_info, io.BytesIO(b"print('x')"))
    assert extract_source_archive(buffer.getvalue()) == {"nested/module.py": "print('x')"}

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(tarfile.TarFile, "extractfile", lambda self, member: None)
    assert extract_source_archive(buffer.getvalue()) == {}
    monkeypatch.undo()


def test_build_error_paths(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    (source_root / "main.py").write_text("print('ok')", encoding="utf-8")

    with pytest.raises(PackageBuildError):
        build_package(source_root, tmp_path / "empty-password.psb", "", "main:run")

    empty_root = tmp_path / "empty"
    empty_root.mkdir()
    with pytest.raises(PackageBuildError):
        build_package(empty_root, tmp_path / "empty-source.psb", "secret", "main:run")


def test_build_reproducible_and_execute(tmp_path: Path) -> None:
    app = _make_sample_app(tmp_path)
    config = BuilderConfig(
        source_dir=str(app),
        entrypoint="app.main:run",
        output_path=str(tmp_path / "sample.psb"),
        reproducible=True,
        sign_package=True,
        transformation=TransformationConfig(
            rename_identifiers=True,
            encrypt_strings=True,
            hide_constants=True,
            insert_dead_code=True,
            flatten_control_flow=True,
            rewrite_imports=True,
        ),
    )

    package_one = PyShieldBuilder(app, "app.main:run", config=config).build(tmp_path / "one.psb", "top-secret")
    package_two = build_package(
        app,
        tmp_path / "two.psb",
        "top-secret",
        "app.main:run",
        transformation=config.transformation,
        reproducible=True,
        sign_package=True,
        package_version=config.package_version,
        metadata_version=config.metadata_version,
    )

    assert package_one.read_bytes() == package_two.read_bytes()

    envelope = json.loads(package_one.read_text(encoding="utf-8"))
    assert envelope["signature"]
    assert envelope["manifest"]["transform_flags"]["encrypt_strings"] is True

    metadata = inspect_package(str(package_one), "top-secret")
    assert metadata.entrypoint == "app.main:run"
    assert metadata.reproducible is True
    assert metadata.transform_flags["rewrite_imports"] is True

    verified = verify_package(str(package_one), "top-secret")
    assert verified.payload_sha256 == metadata.payload_sha256
    assert execute_package(str(package_one), "top-secret") == "run:ok:7:4"


def test_backward_compatible_package_format(tmp_path: Path) -> None:
    app = _make_sample_app(tmp_path)
    sources = collect_source_files(app)
    archive = create_source_archive_from_mapping(sources)
    metadata = {
        "format_version": 1,
        "created_at": "2024-01-01T00:00:00+00:00",
        "entrypoint": "app.main:run",
        "file_count": len(sources),
        "payload_sha256": hashlib.sha256(archive).hexdigest(),
    }
    aad = json.dumps(metadata, sort_keys=True).encode("utf-8")
    salt, nonce, ciphertext = encrypt_bytes(archive, "legacy", aad=aad)
    package_file = tmp_path / "legacy.psb"
    package_file.write_text(
        json.dumps(
            {
                "metadata": metadata,
                "salt": base64.b64encode(salt).decode("ascii"),
                "nonce": base64.b64encode(nonce).decode("ascii"),
                "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    loaded = load_and_decrypt(package_file, "legacy")
    assert loaded.metadata.entrypoint == "app.main:run"
    assert execute_package(str(package_file), "legacy") == "run:ok:7:4"


def test_corrupted_package_and_runtime_protection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    app = _make_sample_app(tmp_path)
    package_file = build_package(app, tmp_path / "broken.psb", "secret", "app.main:run")
    envelope = json.loads(package_file.read_text(encoding="utf-8"))
    envelope["manifest"]["entrypoint"] = "app.main:other"
    package_file.write_text(json.dumps(envelope, indent=2, sort_keys=True), encoding="utf-8")

    with pytest.raises(InvalidPackageError):
        inspect_package(str(package_file), "secret")

    monkeypatch.setattr("builtins.open", lambda *args, **kwargs: None)
    with pytest.raises(RuntimeExecutionError):
        execute_package(str(build_package(app, tmp_path / "prot.psb", "secret", "app.main:run")), "secret")


def test_runtime_edge_cases(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    app = _make_sample_app(tmp_path)
    package_file = build_package(app, tmp_path / "edge.psb", "secret", "app.main:run")

    module = execute_package(str(package_file), "secret", entrypoint="app.main")
    assert module.__name__ == "app.main"

    with pytest.raises(RuntimeExecutionError):
        execute_package(str(package_file), "secret", entrypoint="app.missing:run")

    with pytest.raises(RuntimeExecutionError):
        execute_package(str(package_file), "secret", entrypoint="app.main:missing")

    tampered = json.loads(package_file.read_text(encoding="utf-8"))
    tampered["manifest"]["source_hashes"]["app/main.py"] = "f" * 64
    manifest_bytes = json.dumps(tampered["manifest"], sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    tampered["manifest_sha256"] = hashlib.sha256(manifest_bytes).hexdigest()
    tampered["signature"] = sign_bytes(manifest_bytes, derive_signing_key("secret", base64.b64decode(tampered["salt"])))
    package_file.write_text(json.dumps(tampered, indent=2, sort_keys=True), encoding="utf-8")
    with pytest.raises(InvalidPackageError):
        execute_package(str(package_file), "secret")

    monkeypatch.setattr(runtime, "_SUPPORTED_VERSION", (99, 0))
    with pytest.raises(RuntimeExecutionError):
        execute_package(str(package_file), "secret")

    monkeypatch.setattr(runtime, "_SUPPORTED_VERSION", (3, 12))
    monkeypatch.setattr(runtime.importlib, "import_module", lambda *args, **kwargs: None)
    with pytest.raises(RuntimeExecutionError):
        execute_package(str(package_file), "secret")


def test_manifest_tamper_detection(tmp_path: Path) -> None:
    app = _make_sample_app(tmp_path)
    package_file = build_package(app, tmp_path / "tamper.psb", "secret", "app.main:run")
    envelope = json.loads(package_file.read_text(encoding="utf-8"))
    salt = base64.b64decode(envelope["salt"])
    key = derive_signing_key("secret", salt)

    envelope["signature"] = "0" * 64
    package_file.write_text(json.dumps(envelope, indent=2, sort_keys=True), encoding="utf-8")
    with pytest.raises(InvalidPackageError):
        load_and_decrypt(package_file, "secret")

    envelope = json.loads(package_file.read_text(encoding="utf-8"))
    envelope["manifest_sha256"] = "1" * 64
    envelope["signature"] = sign_bytes(json.dumps(envelope["manifest"], sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8"), key)
    package_file.write_text(json.dumps(envelope, indent=2, sort_keys=True), encoding="utf-8")
    with pytest.raises(InvalidPackageError):
        load_and_decrypt(package_file, "secret")

    envelope = json.loads(package_file.read_text(encoding="utf-8"))
    envelope["manifest"]["payload_sha256"] = "2" * 64
    manifest_bytes = json.dumps(envelope["manifest"], sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    envelope["manifest_sha256"] = hashlib.sha256(manifest_bytes).hexdigest()
    envelope["signature"] = sign_bytes(manifest_bytes, key)
    package_file.write_text(json.dumps(envelope, indent=2, sort_keys=True), encoding="utf-8")
    with pytest.raises(InvalidPackageError):
        load_and_decrypt(package_file, "secret")

    envelope = json.loads(package_file.read_text(encoding="utf-8"))
    envelope.pop("manifest")
    envelope.pop("manifest_sha256")
    envelope.pop("signature")
    package_file.write_text(json.dumps(envelope, indent=2, sort_keys=True), encoding="utf-8")
    with pytest.raises(InvalidPackageError):
        load_and_decrypt(package_file, "secret")


def test_extract_and_verify_helpers(tmp_path: Path) -> None:
    app = _make_sample_app(tmp_path)
    package_file = build_package(app, tmp_path / "helpers.psb", "secret", "app.main:run")
    extracted = extract_package(str(package_file), "secret", tmp_path / "extracted")
    assert extracted
    assert verify_package(str(package_file), "secret").entrypoint == "app.main:run"
