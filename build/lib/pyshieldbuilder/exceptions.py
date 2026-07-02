class ShieldError(Exception):
    """Base error for PyShieldBuilder."""


class BuildError(ShieldError):
    """Raised for build-time failures."""


class VerificationError(ShieldError):
    """Raised when package verification fails."""


class RuntimeProtectionError(ShieldError):
    """Raised when anti-debug protections fail."""
