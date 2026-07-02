from pathlib import Path

import pytest

from pyshieldbuilder.builder import ShieldBuilder
from pyshieldbuilder.config import BuilderConfig
from pyshieldbuilder.exceptions import RuntimeProtectionError
from pyshieldbuilder.loader import ShieldLoader


def test_loader_rejects_tamper(tmp_path: Path):
    source = tmp_path / "src"
    source.mkdir()
    (source / "main.py").write_text("x=1\n", encoding="utf-8")
    package = tmp_path / "test.psb"

    builder = ShieldBuilder(b"secret")
    builder.build(BuilderConfig(source_dir=source, entry_module="main:x", output_file=package))
    data = bytearray(package.read_bytes())
    data[-1] = (data[-1] + 1) % 255

    with pytest.raises(Exception):
        ShieldLoader(b"secret").run(bytes(data))


def test_runtime_protection_detects_trace(monkeypatch):
    monkeypatch.setattr("sys.gettrace", lambda: object())
    with pytest.raises(RuntimeProtectionError):
        ShieldLoader(b"secret").run(b"{}")
