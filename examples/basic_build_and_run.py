"""Example: package and execute a small application."""

from __future__ import annotations

import tempfile
from pathlib import Path

from pyshieldbuilder import PyShieldBuilder, execute_package


def main() -> None:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        app_dir = root / "app"
        app_dir.mkdir(parents=True)
        (app_dir / "__init__.py").write_text("", encoding="utf-8")
        (app_dir / "main.py").write_text(
            "def run():\n    return 'hello from package'\n",
            encoding="utf-8",
        )

        package_path = root / "app.psb"
        builder = PyShieldBuilder(source_dir=app_dir, entrypoint="main:run")
        builder.build(package_path, "change-me")

        result = execute_package(str(package_path), "change-me")
        print(result)


if __name__ == "__main__":
    main()
