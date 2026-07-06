"""Public API for PyShieldBuilder."""

from importlib.metadata import PackageNotFoundError, version

from .builder import PyShieldBuilder, build_package
from .config import BuilderConfig
from .crypto import decrypt_bytes, encrypt_bytes
from .exceptions import (
    DecryptionError,
    InvalidPackageError,
    PackageBuildError,
    RuntimeExecutionError,
)
from .models import TransformationConfig
from .runtime import execute_package, extract_package, inspect_package, verify_package

try:  # pragma: no cover - metadata only
    __version__ = version("pyshieldbuilder")
except PackageNotFoundError:  # pragma: no cover - editable installs
    __version__ = "1.0.0"

__all__ = [
    "BuilderConfig",
    "DecryptionError",
    "InvalidPackageError",
    "PackageBuildError",
    "PyShieldBuilder",
    "RuntimeExecutionError",
    "__version__",
    "build_package",
    "decrypt_bytes",
    "encrypt_bytes",
    "execute_package",
    "extract_package",
    "inspect_package",
    "TransformationConfig",
    "verify_package",
]
