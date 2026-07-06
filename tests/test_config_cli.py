from __future__ import annotations

import json
from pathlib import Path

from pyshieldbuilder.cli import main
from pyshieldbuilder.config import BuilderConfig
from pyshieldbuilder.models import TransformationConfig


def test_config_from_file(tmp_path: Path) -> None:
    config_file = tmp_path / "pyproject.toml"
    config_file.write_text(
        "[tool.pyshieldbuilder]\n"
        "source_dir='src_app'\n"
        "entrypoint='app.main:run'\n"
        "output_path='dist/app.psb'\n"
        "package_version='1.2.3'\n"
        "metadata_version=2\n"
        "reproducible=true\n"
        "sign_package=false\n"
        "\n"
        "[tool.pyshieldbuilder.transform]\n"
        "rename_identifiers=true\n"
        "encrypt_strings=true\n"
        "hide_constants=true\n"
        "insert_dead_code=true\n"
        "flatten_control_flow=true\n"
        "rewrite_imports=true\n",
        encoding="utf-8",
    )

    config = BuilderConfig.from_file(config_file)
    assert config.source_dir == "src_app"
    assert config.entrypoint == "app.main:run"
    assert config.output_path == "dist/app.psb"
    assert config.package_version == "1.2.3"
    assert config.metadata_version == 2
    assert config.reproducible is True
    assert config.sign_package is False
    assert config.transformation == TransformationConfig(
        rename_identifiers=True,
        encrypt_strings=True,
        hide_constants=True,
        insert_dead_code=True,
        flatten_control_flow=True,
        rewrite_imports=True,
    )
    override = config.with_overrides(output_path="dist/other.psb")
    assert override.output_path == "dist/other.psb"


def test_cli_build_inspect_verify_extract_run_benchmark(tmp_path: Path, capsys) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "__init__.py").write_text("", encoding="utf-8")
    (app / "main.py").write_text("def run():\n    return 'cli-ok'\n", encoding="utf-8")

    package = tmp_path / "pkg.psb"
    assert (
        main(
            [
                "build",
                "--source",
                str(tmp_path),
                "--entrypoint",
                "app.main:run",
                "--output",
                str(package),
                "--password",
                "p",
                "--encrypt-strings",
                "--hide-constants",
                "--rewrite-imports",
            ]
        )
        == 0
    )
    build_out = capsys.readouterr().out
    assert str(package.resolve()) in build_out

    assert main(["inspect", "--package", str(package), "--password", "p"]) == 0
    inspect_out = json.loads(capsys.readouterr().out)
    assert inspect_out["entrypoint"] == "app.main:run"

    assert main(["verify", "--package", str(package), "--password", "p"]) == 0
    verify_out = json.loads(capsys.readouterr().out)
    assert verify_out["format_version"] >= 1

    extracted = tmp_path / "extracted"
    assert (
        main(["extract", "--package", str(package), "--password", "p", "--output", str(extracted)])
        == 0
    )
    extract_out = json.loads(capsys.readouterr().out)
    assert extract_out
    assert (extracted / "app" / "main.py").exists()

    assert main(["run", "--package", str(package), "--password", "p"]) == 0
    assert "cli-ok" in capsys.readouterr().out

    assert (
        main(["benchmark", "--package", str(package), "--password", "p", "--iterations", "2"]) == 0
    )
    benchmark_out = json.loads(capsys.readouterr().out)
    assert benchmark_out["iterations"] == 2
    assert benchmark_out["average_seconds"] >= 0


def test_cli_version_doctor_clean(tmp_path: Path, capsys) -> None:
    dist = tmp_path / "dist"
    dist.mkdir()
    old_file = dist / "artifact.psb"
    old_file.write_text("x", encoding="utf-8")

    assert main(["version"]) == 0
    assert capsys.readouterr().out.strip() == "1.0.0"

    assert main(["doctor"]) == 0
    doctor = json.loads(capsys.readouterr().out)
    assert doctor["status"] == "ok"

    assert main(["clean", str(dist)]) == 0
    clean_out = json.loads(capsys.readouterr().out)
    assert str(dist) in clean_out["removed"]
    assert not old_file.exists()
