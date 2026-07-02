"""Runtime utilities for inspecting and executing encrypted packages."""

from __future__ import annotations

import importlib
import importlib.abc
import importlib.util
import sys
from pathlib import PurePosixPath
from types import ModuleType
from typing import Any

from .builder import load_and_decrypt
from .exceptions import RuntimeExecutionError
from .models import PackageMetadata
from .package import extract_source_archive


class _InMemoryLoader(importlib.abc.Loader):
    def __init__(self, module_name: str, source: str) -> None:
        self.module_name = module_name
        self.source = source

    def create_module(self, spec: importlib.machinery.ModuleSpec) -> ModuleType | None:
        return None

    def exec_module(self, module: ModuleType) -> None:
        code = compile(self.source, f"<pyshield:{self.module_name}>", "exec")
        exec(code, module.__dict__)


class _InMemoryFinder(importlib.abc.MetaPathFinder):
    def __init__(self, module_map: dict[str, str]) -> None:
        self._module_map = module_map

    def find_spec(self, fullname: str, path: object | None, target: object | None = None):
        source = self._module_map.get(fullname)
        if source is None:
            return None
        loader = _InMemoryLoader(fullname, source)
        return importlib.util.spec_from_loader(fullname, loader)


def _module_name_from_path(path: str) -> str:
    posix = PurePosixPath(path)
    parts = list(posix.parts)
    if parts[-1] == "__init__.py":
        parts = parts[:-1]
    elif parts[-1].endswith(".py"):
        parts[-1] = parts[-1][:-3]
    return ".".join(parts)


def inspect_package(package_path: str, password: str) -> PackageMetadata:
    """Return package metadata after decrypting and verifying integrity."""
    return load_and_decrypt(package_path, password).metadata


def execute_package(package_path: str, password: str, *, entrypoint: str | None = None) -> Any:
    """Decrypt and execute package from memory-only modules."""
    payload = load_and_decrypt(package_path, password)
    source_map = extract_source_archive(payload.archive_bytes)
    module_map = {_module_name_from_path(path): source for path, source in source_map.items()}

    selected_entrypoint = entrypoint or payload.metadata.entrypoint
    module_name, _, attr_name = selected_entrypoint.partition(":")
    if module_name not in module_map:
        raise RuntimeExecutionError(f"entrypoint module not found: {module_name}")

    finder = _InMemoryFinder(module_map)
    sys.meta_path.insert(0, finder)
    try:
        module = importlib.import_module(module_name)
        if not attr_name:
            return module
        if not hasattr(module, attr_name):
            raise RuntimeExecutionError(f"entrypoint attribute not found: {attr_name}")
        target = getattr(module, attr_name)
        return target() if callable(target) else target
    except RuntimeExecutionError:
        raise
    except Exception as exc:
        raise RuntimeExecutionError("failed to execute package") from exc
    finally:
        if finder in sys.meta_path:
            sys.meta_path.remove(finder)
