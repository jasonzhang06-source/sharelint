"""Mutable scan session state with centralized privacy and resource limits."""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import Finding, ScanError, ScanLimits, ScanSurface, SurfaceStatus
from .privacy import EvidenceProtector, mask_evidence
from .rules import get_rule


@dataclass(slots=True)
class ScanContext:
    limits: ScanLimits
    protector: EvidenceProtector = field(default_factory=EvidenceProtector)
    findings: list[Finding] = field(default_factory=list)
    surfaces: list[ScanSurface] = field(default_factory=list)
    errors: list[ScanError] = field(default_factory=list)
    total_bytes: int = 0
    archive_members: int = 0
    finding_limit_reached: bool = False
    _finding_keys: set[tuple[str, tuple[str, ...], str, str]] = field(default_factory=set)
    _path_aliases: dict[str, str] = field(default_factory=dict)

    def display_path(self, name: str) -> str:
        """Redact a path while keeping colliding redactions distinguishable."""

        from .scanners.path import redact_path

        redacted = redact_path(name)
        if redacted == name:
            return redacted
        return f"{redacted} [path-ref:{self.path_reference(name)}]"

    def path_reference(self, name: str) -> str:
        """Return a report-local opaque ordinal for a raw logical path."""

        alias = self._path_aliases.get(name)
        if alias is None:
            alias = f"p{len(self._path_aliases) + 1:04d}"
            self._path_aliases[name] = alias
        return alias

    def add_finding(
        self,
        rule_id: str,
        source_chain: tuple[str, ...],
        location: str,
        evidence: str,
        *,
        evidence_kind: str = "generic",
    ) -> bool:
        if self.finding_limit_reached:
            return False
        if len(self.findings) >= self.limits.max_findings:
            self.finding_limit_reached = True
            self.errors.append(
                ScanError(
                    source_chain,
                    "SL.ARCHIVE.LIMIT_EXCEEDED",
                    "Finding count limit reached; remaining matches were not recorded",
                )
            )
            self.add_surface(
                source_chain,
                "finding-ledger",
                SurfaceStatus.PARTIAL,
                0,
                "reporting",
                "finding count limit reached",
            )
            return False
        rule = get_rule(rule_id)
        fingerprint = self.protector.fingerprint(rule_id, evidence)
        key = (rule_id, source_chain, location, fingerprint)
        if key in self._finding_keys:
            return True
        self._finding_keys.add(key)
        self.findings.append(
            Finding(
                rule_id=rule.rule_id,
                severity=rule.severity,
                title=rule.title,
                source_chain=source_chain,
                location=location,
                masked_preview=mask_evidence(evidence, evidence_kind),
                evidence_fingerprint=fingerprint,
                remediation=rule.remediation,
                tags=rule.tags,
            )
        )
        return True

    def add_surface(
        self,
        source_chain: tuple[str, ...],
        kind: str,
        status: SurfaceStatus,
        bytes_inspected: int,
        scanner: str,
        note: str = "",
    ) -> None:
        self.surfaces.append(
            ScanSurface(
                source_chain=source_chain,
                kind=kind,
                status=status,
                bytes_inspected=max(0, bytes_inspected),
                scanner=scanner,
                note=note,
            )
        )

    def add_error(self, source_chain: tuple[str, ...], code: str, message: str) -> None:
        # Parser exception strings can contain raw content. Callers provide bounded,
        # content-free messages instead of forwarding exception text.
        self.errors.append(ScanError(source_chain, code, message[:240]))

    def consume(self, amount: int) -> bool:
        if amount < 0 or self.total_bytes + amount > self.limits.max_total_bytes:
            return False
        self.total_bytes += amount
        return True

    @property
    def remaining_bytes(self) -> int:
        return max(0, self.limits.max_total_bytes - self.total_bytes)

    def consume_member(self) -> bool:
        if self.archive_members + 1 > self.limits.max_archive_members:
            return False
        self.archive_members += 1
        return True
