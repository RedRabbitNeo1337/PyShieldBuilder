"""Exception types used by PyShieldBuilder."""


class PyShieldBuilderError(Exception):
    """Base class for project exceptions."""


class PackageBuildError(PyShieldBuilderError):
    """Raised when package construction fails."""


class InvalidPackageError(PyShieldBuilderError):
    """Raised when a package cannot be parsed or validated."""


class DecryptionError(PyShieldBuilderError):
    """Raised when encrypted payload decryption fails."""


class RuntimeExecutionError(PyShieldBuilderError):
    """Raised when runtime execution fails."""
