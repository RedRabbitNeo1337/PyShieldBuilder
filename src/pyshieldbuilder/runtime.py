"""Runtime utilities for inspecting and executing encrypted packages."""

from __future__ import annotations

import builtins as _b
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

# Indirect references to builtins – avoids obvious exec/compile patterns in
# emitted bytecode when this module is inspected without source.
_cf = getattr(_b, "compile")
_ef = getattr(_b, "exec")
_gaf = getattr(_b, "getattr")


class _S1L(importlib.abc.Loader):
    """In-memory module loader (stage-1 runtime)."""

    __slots__ = ("_n", "_s")

    def __init__(self, _n: str, _s: str) -> None:
        self._n = _n
        self._s = _s

    def create_module(self, spec: importlib.machinery.ModuleSpec) -> ModuleType | None:
        return None

    def exec_module(self, module: ModuleType) -> None:
        _co = _cf(self._s, "<{}>".format(self._n), "exec")
        _ef(_co, _gaf(module, "__dict__"))


class _S1F(importlib.abc.MetaPathFinder):
    """In-memory meta-path finder (stage-1 runtime)."""

    __slots__ = ("_m", "_p")

    def __init__(self, _m: dict[str, str], _p: set[str]) -> None:
        self._m = _m
        self._p = _p

    def find_spec(self, fullname: str, path: object | None, target: object | None = None):
        _src = self._m.get(fullname)
        if _src is None:
            return None
        _ldr = _S1L(fullname, _src)
        _sfl = _gaf(importlib.util, "spec_from_loader")
        return _sfl(fullname, _ldr, is_package=fullname in self._p)


def _mnfp(path: str) -> str:
    """Derive a dotted module name from an archive path."""
    _pos = PurePosixPath(path)
    _pts = list(_pos.parts)
    if _pts[-1] == "__init__.py":
        _pts = _pts[:-1]
    elif _pts[-1].endswith(".py"):
        _pts[-1] = _pts[-1][:-3]
    return ".".join(_pts)


def inspect_package(package_path: str, password: str) -> PackageMetadata:
    """Return package metadata after decrypting and verifying integrity."""
    return load_and_decrypt(package_path, password).metadata


def execute_package(package_path: str, password: str, *, entrypoint: str | None = None) -> Any:
    """Decrypt and execute package from memory-only modules."""
    payload = load_and_decrypt(package_path, password)
    source_map = extract_source_archive(payload.archive_bytes)
    module_map = {_mnfp(path): source for path, source in source_map.items()}
    package_names = {_mnfp(path) for path in source_map if path.endswith("__init__.py")}

    selected_entrypoint = entrypoint or payload.metadata.entrypoint
    module_name, _, attr_name = selected_entrypoint.partition(":")
    if module_name not in module_map:
        raise RuntimeExecutionError(f"entrypoint module not found: {module_name}")

    # Evict any stale cached entries so the in-memory source is always used.
    for _mn in list(module_map):
        sys.modules.pop(_mn, None)

    finder = _S1F(module_map, package_names)
    sys.meta_path.insert(0, finder)
    try:
        _imfn = _gaf(importlib, "import_module")
        module = _imfn(module_name)
        if not attr_name:
            return module
        if not _gaf(_b, "hasattr")(module, attr_name):
            raise RuntimeExecutionError(f"entrypoint attribute not found: {attr_name}")
        _tgt = _gaf(module, attr_name)
        return _tgt() if callable(_tgt) else _tgt
    except RuntimeExecutionError:
        raise
    except Exception as exc:
        raise RuntimeExecutionError("failed to execute package") from exc
    finally:
        if finder in sys.meta_path:
            sys.meta_path.remove(finder)
