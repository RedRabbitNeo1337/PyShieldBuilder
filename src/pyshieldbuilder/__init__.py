"""Public API for PyShieldBuilder."""

from .builder import PyShieldBuilder, build_package
from .config import BuilderConfig
from .crypto import decrypt_bytes, encrypt_bytes
from .exceptions import (
    DecryptionError,
    InvalidPackageError,
    PackageBuildError,
    RuntimeExecutionError,
)
from .runtime import execute_package, inspect_package
from .stage1 import _PPLN as PROTECTION_PIPELINE, _PV as PROTECTION_VERSION, _RV as RUNTIME_VERSION

__all__ = [
    "PROTECTION_PIPELINE",
    "PROTECTION_VERSION",
    "RUNTIME_VERSION",
    "BuilderConfig",
    "DecryptionError",
    "InvalidPackageError",
    "PackageBuildError",
    "PyShieldBuilder",
    "RuntimeExecutionError",
    "build_package",
    "decrypt_bytes",
    "encrypt_bytes",
    "execute_package",
    "inspect_package",
]
