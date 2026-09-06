"""ShareLint public package API."""

from ._version import __version__
from .models import Finding, ScanLimits, ScanReport, ScanSurface, Severity
from .scanner import scan
from .verification import VerificationError, VerificationResult, verify_receipt

__all__ = [
    "Finding",
    "ScanLimits",
    "ScanReport",
    "ScanSurface",
    "Severity",
    "VerificationError",
    "VerificationResult",
    "__version__",
    "scan",
    "verify_receipt",
]
