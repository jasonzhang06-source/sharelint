"""Stable data contracts used by scanners, reporters, and pack receipts."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from ._version import __version__


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }[self]

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls(value.lower())
        except ValueError as exc:
            choices = ", ".join(item.value for item in cls)
            raise ValueError(f"severity must be one of: {choices}") from exc


class SurfaceStatus(StrEnum):
    SCANNED = "scanned"
    PARTIAL = "partial"
    SKIPPED = "skipped"


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    severity: Severity
    title: str
    source_chain: tuple[str, ...]
    location: str
    masked_preview: str
    evidence_fingerprint: str
    remediation: str
    tags: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "title": self.title,
            "source_chain": list(self.source_chain),
            "location": self.location,
            "masked_preview": self.masked_preview,
            "evidence_fingerprint": self.evidence_fingerprint,
            "remediation": self.remediation,
            "tags": list(self.tags),
        }


@dataclass(frozen=True, slots=True)
class ScanSurface:
    source_chain: tuple[str, ...]
    kind: str
    status: SurfaceStatus
    bytes_inspected: int
    scanner: str
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "source_chain": list(self.source_chain),
            "kind": self.kind,
            "status": self.status.value,
            "bytes_inspected": self.bytes_inspected,
            "scanner": self.scanner,
        }
        if self.note:
            result["note"] = self.note
        return result


@dataclass(frozen=True, slots=True)
class ScanError:
    source_chain: tuple[str, ...]
    code: str
    message: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_chain": list(self.source_chain),
            "code": self.code,
            "message": self.message,
        }


@dataclass(frozen=True, slots=True)
class ScanLimits:
    max_file_bytes: int = 64 * 1024 * 1024
    max_member_bytes: int = 32 * 1024 * 1024
    max_total_bytes: int = 256 * 1024 * 1024
    max_archive_depth: int = 4
    max_archive_members: int = 10_000
    max_compression_ratio: float = 200.0
    max_text_chars: int = 8_000_000
    max_xml_elements: int = 100_000
    max_findings: int = 10_000

    def __post_init__(self) -> None:
        integer_limits = (
            self.max_file_bytes,
            self.max_member_bytes,
            self.max_total_bytes,
            self.max_archive_depth,
            self.max_archive_members,
            self.max_text_chars,
            self.max_xml_elements,
            self.max_findings,
        )
        if any(type(value) is not int or value <= 0 for value in integer_limits):
            raise ValueError("scan limits must be positive integers")
        if (
            isinstance(self.max_compression_ratio, bool)
            or not isinstance(self.max_compression_ratio, (int, float))
            or not math.isfinite(self.max_compression_ratio)
            or self.max_compression_ratio <= 0
        ):
            raise ValueError("max_compression_ratio must be finite and positive")

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_file_bytes": self.max_file_bytes,
            "max_member_bytes": self.max_member_bytes,
            "max_total_bytes": self.max_total_bytes,
            "max_archive_depth": self.max_archive_depth,
            "max_archive_members": self.max_archive_members,
            "max_compression_ratio": self.max_compression_ratio,
            "max_text_chars": self.max_text_chars,
            "max_xml_elements": self.max_xml_elements,
            "max_findings": self.max_findings,
        }


@dataclass(slots=True)
class ScanReport:
    target_name: str
    target_kind: str
    target_sha256: str
    fingerprint_scope: str
    limits: ScanLimits
    findings: list[Finding] = field(default_factory=list)
    surfaces: list[ScanSurface] = field(default_factory=list)
    errors: list[ScanError] = field(default_factory=list)
    tool_version: str = __version__
    schema_version: str = "1.0.0"

    @property
    def maximum_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max((item.severity for item in self.findings), key=lambda item: item.rank)

    def count_at_or_above(self, threshold: Severity) -> int:
        return sum(item.severity.rank >= threshold.rank for item in self.findings)

    @property
    def has_coverage_gaps(self) -> bool:
        return bool(self.errors) or any(
            surface.status is not SurfaceStatus.SCANNED for surface in self.surfaces
        )

    def summary(self, threshold: Severity = Severity.HIGH) -> dict[str, Any]:
        by_severity = {severity.value: 0 for severity in Severity}
        for finding in self.findings:
            by_severity[finding.severity.value] += 1
        by_status = {status.value: 0 for status in SurfaceStatus}
        for surface in self.surfaces:
            by_status[surface.status.value] += 1
        blockers = self.count_at_or_above(threshold)
        if self.has_coverage_gaps:
            verdict = "incomplete"
        elif blockers:
            verdict = "blocked"
        else:
            verdict = "pass"
        return {
            "verdict": verdict,
            "fail_on": threshold.value,
            "blocking_findings": blockers,
            "total_findings": len(self.findings),
            "findings_by_severity": by_severity,
            "surface_count": len(self.surfaces),
            "surfaces_by_status": by_status,
            "bytes_inspected": sum(surface.bytes_inspected for surface in self.surfaces),
            "error_count": len(self.errors),
            "coverage_complete": not self.has_coverage_gaps,
        }

    def to_dict(self, threshold: Severity = Severity.HIGH) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "tool": {"name": "sharelint", "version": self.tool_version},
            "scan": {
                "target": {
                    "name": self.target_name,
                    "kind": self.target_kind,
                    "sha256": self.target_sha256,
                },
                "fingerprint_scope": self.fingerprint_scope,
                "limits": self.limits.to_dict(),
            },
            "summary": self.summary(threshold),
            "findings": [item.to_dict() for item in self.findings],
            "surfaces": [item.to_dict() for item in self.surfaces],
            "errors": [item.to_dict() for item in self.errors],
        }
