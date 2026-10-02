"""Bounded, sequential multi-target preflight with private aggregate results."""

from __future__ import annotations

import hashlib
import html
import json
import os
import tomllib
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from ._version import __version__
from .context import ScanContext
from .input_io import DocumentInputError, read_document
from .models import ScanLimits, Severity
from .reporters import render_json
from .scanner import ScanInputError, _scan_with_context

MAX_MANIFEST_BYTES = 64 * 1024
_CLAIM = (
    "Local aggregate preflight, not a safety guarantee. Target IDs follow input order; "
    "filenames and matched evidence are not included. Every target needs complete coverage."
)


@dataclass(frozen=True, slots=True)
class BatchLimits:
    max_targets: int = 100
    max_total_bytes: int = 1024 * 1024 * 1024

    def __post_init__(self) -> None:
        if type(self.max_targets) is not int or not 1 <= self.max_targets <= 1000:
            raise DocumentInputError("batch target limit must be an integer between 1 and 1000")
        if type(self.max_total_bytes) is not int or not 1 <= self.max_total_bytes < 2**63:
            raise DocumentInputError("batch byte limit must be a positive signed 64-bit integer")

    def to_dict(self) -> dict[str, int]:
        return {"max_targets": self.max_targets, "max_total_bytes": self.max_total_bytes}


def resolve_targets(
    targets: Iterable[str | os.PathLike[str]], *, maximum: int = 100, base: Path | None = None
) -> tuple[Path, ...]:
    BatchLimits(max_targets=maximum)
    if isinstance(targets, (str, bytes, os.PathLike)):
        raise DocumentInputError("batch targets must be a sequence of explicit paths")
    resolved: list[Path] = []
    identities: set[str] = set()
    for index, value in enumerate(targets):
        if index >= maximum:
            raise DocumentInputError("batch target count exceeds the configured limit")
        try:
            name = os.fspath(value)
        except TypeError as exc:
            raise DocumentInputError("batch target must be a bounded path string") from exc
        if not isinstance(name, str) or not name or len(name) > 4096 or "\0" in name:
            raise DocumentInputError("batch target must be a bounded path string")
        path = Path(name)
        if base is not None and not path.is_absolute():
            path = base / path
        path = Path(os.path.abspath(path))
        identity = os.path.normcase(str(path))
        if identity in identities:
            raise DocumentInputError("batch contains duplicate normalized target paths")
        identities.add(identity)
        resolved.append(path)
    if not resolved:
        raise DocumentInputError("batch requires at least one explicit target")
    return tuple(resolved)


def read_batch_manifest(path: Path, *, maximum: int = 100) -> tuple[Path, ...]:
    data = read_document(path, MAX_MANIFEST_BYTES)
    try:
        document = tomllib.loads(data.decode("utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise DocumentInputError("batch manifest must be valid UTF-8 TOML") from exc
    if (
        set(document) != {"schema_version", "targets"}
        or type(document["schema_version"]) is not int
        or document["schema_version"] != 1
        or not isinstance(document["targets"], list)
    ):
        raise DocumentInputError("batch manifest requires schema_version 1 and a targets array")
    return resolve_targets(document["targets"], maximum=maximum, base=path.absolute().parent)


@dataclass(frozen=True, slots=True)
class BatchEntry:
    target_id: str
    status: str
    reason: str
    charged_bytes: int
    target_sha256: str | None
    report_sha256: str | None
    effective_limits: ScanLimits | None
    summary: dict[str, Any] | None
    rules: tuple[dict[str, Any], ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "status": self.status,
            "reason": self.reason,
            "charged_bytes": self.charged_bytes,
            "target_sha256": self.target_sha256,
            "report_sha256": self.report_sha256,
            "effective_limits": self.effective_limits.to_dict() if self.effective_limits else None,
            "summary": self.summary,
            "rules": list(self.rules),
        }


@dataclass(frozen=True, slots=True)
class BatchResult:
    entries: tuple[BatchEntry, ...]
    limits: BatchLimits
    scan_limits: ScanLimits
    threshold: Severity

    def __post_init__(self) -> None:
        if not self.entries or len(self.entries) > self.limits.max_targets:
            raise DocumentInputError("batch result must contain the bounded selected targets")

    @property
    def status(self) -> str:
        states = {entry.status for entry in self.entries}
        if "error" in states:
            return "error"
        if states & {"not-scanned", "incomplete"}:
            return "incomplete"
        return "blocked" if "blocked" in states else "pass"

    @property
    def exit_code(self) -> int:
        return 2 if self.status == "error" else 0 if self.status == "pass" else 1

    def to_dict(self) -> dict[str, Any]:
        counts = Counter(entry.status for entry in self.entries)
        return {
            "schema_version": "1.0.0",
            "batch_type": "sharelint.batch-preflight",
            "tool": {"name": "sharelint", "version": __version__},
            "status": self.status,
            "fail_on": self.threshold.value,
            "require_complete_coverage": True,
            "batch_limits": self.limits.to_dict(),
            "scan_limits": self.scan_limits.to_dict(),
            "summary": {
                "target_count": len(self.entries),
                "targets_by_status": {
                    status: counts[status]
                    for status in ("pass", "blocked", "incomplete", "error", "not-scanned")
                },
                "charged_bytes": sum(entry.charged_bytes for entry in self.entries),
                "coverage_complete": not set(counts) & {"error", "incomplete", "not-scanned"},
            },
            "entries": [entry.to_dict() for entry in self.entries],
            "claim": _CLAIM,
        }

    def render(self, format_name: str = "console") -> str:
        if format_name == "json":
            return json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n"
        rows = [
            (
                entry.target_id,
                entry.status.upper(),
                entry.summary["total_findings"] if entry.summary else "unavailable",
                entry.reason,
            )
            for entry in self.entries
        ]
        if format_name == "html":
            body = "".join(
                "<tr>" + "".join(f"<td>{html.escape(str(value))}</td>" for value in row) + "</tr>"
                for row in rows
            )
            return (
                '<!doctype html><html lang="en"><meta charset="utf-8">'
                '<meta name="viewport" content="width=device-width,initial-scale=1">'
                "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">"
                "<title>ShareLint batch preflight</title><style>"
                "body{font:16px system-ui;max-width:70rem;margin:2rem auto;padding:1rem;background:#101923;color:#e3f2ee}"
                "table{width:100%;border-collapse:collapse}td,th{padding:.7rem;text-align:left;border-bottom:1px solid #465b65}"
                "h1{color:#56dec0}p{line-height:1.6}</style>"
                f"<h1>Batch: {self.status.upper()}</h1><p>{html.escape(_CLAIM)}</p>"
                "<table><thead><tr><th>Target</th><th>Status</th><th>Findings</th><th>Reason</th></tr></thead>"
                f"<tbody>{body}</tbody></table></html>\n"
            )
        if format_name != "console":
            raise DocumentInputError("unsupported batch output format")
        lines = [f"BATCH {self.status.upper()} · {len(self.entries)} target(s)"]
        lines.extend(
            f"{name} · {status} · {count} finding(s) · {reason}"
            for name, status, count, reason in rows
        )
        lines.append(_CLAIM)
        return "\n".join(lines) + "\n"


def scan_batch(
    targets: Iterable[str | os.PathLike[str]],
    *,
    limits: ScanLimits | None = None,
    batch_limits: BatchLimits | None = None,
    fail_on: Severity = Severity.HIGH,
) -> BatchResult:
    budget = batch_limits or BatchLimits()
    selected = resolve_targets(targets, maximum=budget.max_targets)
    configured = limits or ScanLimits()
    remaining = budget.max_total_bytes
    entries: list[BatchEntry] = []
    for index, path in enumerate(selected):
        target_id = f"t{index + 1:04d}"
        if remaining == 0:
            entries.append(
                BatchEntry(
                    target_id, "not-scanned", "batch-byte-limit", 0, None, None, None, None, ()
                )
            )
            continue
        effective = replace(configured, max_total_bytes=min(configured.max_total_bytes, remaining))
        context = ScanContext(effective)
        try:
            report = _scan_with_context(path, context)
        except (ScanInputError, OSError):
            entries.append(
                BatchEntry(
                    target_id,
                    "error",
                    "input-error",
                    context.total_bytes,
                    None,
                    None,
                    effective,
                    None,
                    (),
                )
            )
        else:
            summary = report.summary(fail_on)
            status = summary["verdict"] if report.surfaces else "incomplete"
            reason = {"pass": "complete", "blocked": "policy-block", "incomplete": "coverage-gap"}[
                status
            ]
            counts = Counter(
                (finding.rule_id, finding.severity.value) for finding in report.findings
            )
            entries.append(
                BatchEntry(
                    target_id,
                    status,
                    reason,
                    context.total_bytes,
                    report.target_sha256,
                    hashlib.sha256(render_json(report, fail_on).encode("utf-8")).hexdigest(),
                    effective,
                    summary,
                    tuple(
                        {"rule_id": rule, "severity": severity, "count": count}
                        for (rule, severity), count in sorted(counts.items())
                    ),
                )
            )
        remaining -= context.total_bytes
    return BatchResult(tuple(entries), budget, configured, fail_on)
