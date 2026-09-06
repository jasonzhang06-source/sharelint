"""ShareLint public package API."""

from ._version import __version__
from .batch import BatchLimits, BatchResult, scan_batch
from .comparison import ReportComparison, compare_reports
from .models import Finding, ScanLimits, ScanReport, ScanSurface, Severity
from .planning import HandoffPlan, create_plan, read_plan
from .scanner import scan
from .verification import VerificationError, VerificationResult, verify_receipt

__all__ = [
    "BatchLimits",
    "BatchResult",
    "Finding",
    "HandoffPlan",
    "ReportComparison",
    "ScanLimits",
    "ScanReport",
    "ScanSurface",
    "Severity",
    "VerificationError",
    "VerificationResult",
    "__version__",
    "compare_reports",
    "create_plan",
    "read_plan",
    "scan",
    "scan_batch",
    "verify_receipt",
]
