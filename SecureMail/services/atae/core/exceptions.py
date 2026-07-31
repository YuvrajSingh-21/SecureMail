class ATAEError(Exception):
    """Base exception for ATAE."""

class ATAEParserError(ATAEError):
    """Raised when an analyzer fails to parse a file structurally."""

class ATAETimeoutError(ATAEError):
    """Raised when an analysis stage exceeds its time limit."""

class ATAEResourceExhaustionError(ATAEError):
    """Raised when resource limits are exceeded."""

class ATAEArchiveBombError(ATAEResourceExhaustionError):
    """Raised when an archive bomb is detected."""

class ATAESecurityError(ATAEError):
    """Raised for security boundaries (e.g. escaping workspace)."""

class ATAEUnsupportedTypeError(ATAEError):
    """Raised when no analyzer can handle the file type."""
