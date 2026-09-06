"""ShareLint public package API."""

from ._version import __version__
from .comparison import ReportComparison, compare_reports
from .models import Finding, ScanLimits, ScanReport, ScanSurface, Severity
from .scanner import scan
from .verification import VerificationError, VerificationResult, verify_receipt

__all__ = [
    "Finding",
    "ReportComparison",
    "ScanLimits",
    "ScanReport",
    "ScanSurface",
    "Severity",
    "VerificationError",
    "VerificationResult",
    "__version__",
    "compare_reports",
    "scan",
    "verify_receipt",
]
