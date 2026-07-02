import os
import sys
from types import BuiltinFunctionType

from pyshieldbuilder.exceptions import RuntimeProtectionError


def enforce_runtime_protections() -> None:
    if sys.gettrace() is not None:
        raise RuntimeProtectionError("debugger/tracer detected")

    if os.name == "posix":
        try:
            with open("/proc/self/status", encoding="utf-8") as fh:
                status = fh.read()
            if "TracerPid:	0" not in status:
                raise RuntimeProtectionError("ptrace tracer detected")
        except FileNotFoundError:
            pass

    if not isinstance(exec, BuiltinFunctionType):
        raise RuntimeProtectionError("exec monkeypatch detected")

    if os.getenv("PYTHONBREAKPOINT") not in (None, "", "0"):
        raise RuntimeProtectionError("debug breakpoint hook detected")
