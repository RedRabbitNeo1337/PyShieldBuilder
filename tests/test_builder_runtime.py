from pathlib import Path

from pyshieldbuilder.builder import PyShieldBuilder, load_and_decrypt
from pyshieldbuilder.package import extract_source_archive
from pyshieldbuilder.runtime import execute_package, inspect_package


def _make_sample_app(base: Path) -> Path:
    app = base / "app"
    app.mkdir()
    (app / "__init__.py").write_text("", encoding="utf-8")
    (app / "helpers.py").write_text(
        "def message():\n    return 'ok'\n",
        encoding="utf-8",
    )
    (app / "main.py").write_text(
        "from app.helpers import message\n"
        "def run():\n"
        "    return f'run:{message()}'\n",
        encoding="utf-8",
    )
    return app


def test_build_inspect_execute(tmp_path: Path) -> None:
    _make_sample_app(tmp_path)
    package_path = tmp_path / "sample.psb"

    builder = PyShieldBuilder(source_dir=tmp_path, entrypoint="app.main:run")
    builder.build(package_path, "top-secret")

    metadata = inspect_package(str(package_path), "top-secret")
    assert metadata.entrypoint == "app.main:run"
    assert metadata.file_count == 3
    assert metadata.stage1_enabled is True
    assert metadata.source_protection == "marshal+zlib+base85"

    payload = load_and_decrypt(str(package_path), "top-secret")
    source_map = extract_source_archive(payload.archive_bytes)
    assert "exec(_m.loads(_z.decompress(_b64.b85decode(" in source_map["app/main.py"]
    assert "return f'run:{message()}'" not in source_map["app/main.py"]

    result = execute_package(str(package_path), "top-secret")
    assert result == "run:ok"
