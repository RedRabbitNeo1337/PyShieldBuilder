import json
from pathlib import Path

from pyshieldbuilder.cli import main
from pyshieldbuilder.config import BuilderConfig


def test_config_from_file(tmp_path: Path) -> None:
    config_file = tmp_path / "pyproject.toml"
    config_file.write_text(
        "[tool.pyshieldbuilder]\n"
        "source_dir='src_app'\n"
        "entrypoint='app.main:run'\n"
        "output_path='dist/app.psb'\n",
        encoding="utf-8",
    )

    config = BuilderConfig.from_file(config_file)
    assert config.source_dir == "src_app"
    assert config.entrypoint == "app.main:run"
    assert config.output_path == "dist/app.psb"


def test_cli_build_inspect_run(tmp_path: Path, capsys) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "main.py").write_text("def run():\n    return 'cli-ok'\n", encoding="utf-8")

    package = tmp_path / "pkg.psb"
    assert main([
        "build",
        "--source",
        str(app),
        "--entrypoint",
        "main:run",
        "--output",
        str(package),
        "--password",
        "p",
    ]) == 0

    out = capsys.readouterr().out
    assert str(package.resolve()) in out

    assert main(["inspect", "--package", str(package), "--password", "p"]) == 0
    inspect_out = capsys.readouterr().out
    parsed = json.loads(inspect_out)
    assert parsed["entrypoint"] == "main:run"

    assert main(["run", "--package", str(package), "--password", "p"]) == 0
    run_out = capsys.readouterr().out
    assert "cli-ok" in run_out
