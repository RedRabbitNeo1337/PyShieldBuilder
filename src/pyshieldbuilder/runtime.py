"""Runtime utilities for inspecting and executing encrypted packages."""

from __future__ import annotations

import builtins
import importlib
import importlib.abc
import importlib.util
import hashlib
import sys
from pathlib import Path, PurePosixPath
from types import ModuleType
from typing import Any

from .builder import load_and_decrypt
from .exceptions import InvalidPackageError, RuntimeExecutionError
from .models import PackageMetadata
from .package import extract_source_archive, extract_source_archive_to_directory

_ORIGINAL_OPEN = builtins.open
_ORIGINAL_IMPORT_MODULE = importlib.import_module
_SUPPORTED_VERSION = (3, 12)


class _InMemoryLoader(importlib.abc.Loader):
    def __init__(self, module_name: str, source: str, *, code_cache: dict[str, object]) -> None:
        self.module_name = module_name
        self.source = source
        self._code_cache = code_cache

    def create_module(self, spec: importlib.machinery.ModuleSpec) -> ModuleType | None:
        return None

    def exec_module(self, module: ModuleType) -> None:
        code = self._code_cache.get(self.module_name)
        if code is None:
            code = compile(self.source, f"<pyshield:{self.module_name}>", "exec")
            self._code_cache[self.module_name] = code
        exec(code, module.__dict__)


class _InMemoryFinder(importlib.abc.MetaPathFinder):
    def __init__(self, module_map: dict[str, str], package_names: set[str]) -> None:
        self._module_map = module_map
        self._package_names = package_names
        self._code_cache: dict[str, object] = {}

    def find_spec(self, fullname: str, path: object | None, target: object | None = None):
        source = self._module_map.get(fullname)
        if source is None:
            return None
        loader = _InMemoryLoader(fullname, source, code_cache=self._code_cache)
        return importlib.util.spec_from_loader(fullname, loader, is_package=fullname in self._package_names)


def _module_name_from_path(path: str) -> str:
    posix = PurePosixPath(path)
    parts = list(posix.parts)
    if parts and parts[-1] == "__init__.py":
        parts = parts[:-1]
    elif parts and parts[-1].endswith(".py"):
        parts[-1] = parts[-1][:-3]
    return ".".join(part for part in parts if part)


def _validate_runtime_environment() -> None:
    if sys.version_info < _SUPPORTED_VERSION:
        raise RuntimeExecutionError("Python 3.12 or newer is required")
    if builtins.open is not _ORIGINAL_OPEN or importlib.import_module is not _ORIGINAL_IMPORT_MODULE:
        raise RuntimeExecutionError("runtime monkey patch detected")


def inspect_package(package_path: str, password: str) -> PackageMetadata:
    """Return package metadata after decrypting and verifying integrity."""
    return load_and_decrypt(package_path, password).metadata


def verify_package(package_path: str, password: str) -> PackageMetadata:
    """Verify package integrity and return metadata."""
    return inspect_package(package_path, password)


def extract_package(package_path: str, password: str, destination: str | Path) -> list[Path]:
    """Decrypt a package and write its source files to *destination*."""
    payload = load_and_decrypt(package_path, password)
    return extract_source_archive_to_directory(payload.archive_bytes, destination)


def execute_package(package_path: str, password: str, *, entrypoint: str | None = None) -> Any:
    """Decrypt and execute package from memory-only modules."""
    _validate_runtime_environment()
    payload = load_and_decrypt(package_path, password)
    source_map = extract_source_archive(payload.archive_bytes)
    _verify_source_integrity(source_map, payload.metadata)
    module_map = {_module_name_from_path(path): source for path, source in source_map.items()}
    package_names = {
        _module_name_from_path(path)
        for path in source_map
        if path.endswith("__init__.py")
    }

    selected_entrypoint = entrypoint or payload.metadata.entrypoint
    module_name, _, attr_name = selected_entrypoint.partition(":")
    if module_name not in module_map:
        raise RuntimeExecutionError(f"entrypoint module not found: {module_name}")

    finder = _InMemoryFinder(module_map, package_names)
    previous_modules = _clear_loaded_modules(module_map)
    sys.meta_path.insert(0, finder)
    importlib.invalidate_caches()
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
        _restore_loaded_modules(previous_modules)
        importlib.invalidate_caches()


def _verify_source_integrity(source_map: dict[str, str], metadata: PackageMetadata) -> None:
    expected = metadata.source_hashes
    if not expected:
        return
    for path, source in source_map.items():
        digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
        if expected.get(path) != digest:
            raise InvalidPackageError(f"source integrity verification failed: {path}")


def _clear_loaded_modules(module_map: dict[str, str]) -> dict[str, ModuleType]:
    previous: dict[str, ModuleType] = {}
    for module_name in module_map:
        if module_name in sys.modules:
            previous[module_name] = sys.modules.pop(module_name)
    return previous


def _restore_loaded_modules(previous: dict[str, ModuleType]) -> None:
    for module_name, module in previous.items():
        sys.modules[module_name] = module
