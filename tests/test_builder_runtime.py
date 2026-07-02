from pathlib import Path

from pyshieldbuilder.builder import ShieldBuilder
from pyshieldbuilder.config import BuilderConfig


def test_build_produces_package(tmp_path: Path):
    source = tmp_path / "src"
    source.mkdir()
    (source / "main.py").write_text("x=1\n", encoding="utf-8")
    output = tmp_path / "out.psb"

    builder = ShieldBuilder(b"secret")
    produced = builder.build(BuilderConfig(source_dir=source, entry_module="main:x", output_file=output))
    assert produced.exists()
    assert produced.read_bytes()
