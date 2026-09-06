"""Freshly checked, non-overwriting text-derivative publication and verification."""

from __future__ import annotations

import hashlib
import os
import re
import tempfile
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ._version import __version__
from .documents import (
    MAX_DOCUMENT_BYTES,
    digest,
    integer,
    object_fields,
    parse_json,
    require,
    string,
    validate_limits,
    validate_report,
)
from .input_io import DocumentInputError, read_document
from .models import ScanLimits, ScanReport, Severity
from .packing import (
    PackError,
    _commit_publications,
    _publish_without_overwrite,
    _PublishedFile,
    _unlink_published,
    _write_bytes,
    _write_document,
)
from .planning import boundary_sha256, snapshot_sha256
from .policy import policy_document
from .redaction import RedactionBlocked, RedactionPlan, _prepare, _summary, read_redaction_plan
from .reporters import render_json
from .scanner import scan
from .text_edits import MAX_REDACTION_BYTES
from .verification import VerificationError

_CLAIM = (
    "A locally rescanned text derivative, not a safety guarantee or signature. "
    "Original source bytes were not overwritten. Unsupported and undetected content may remain."
)


@dataclass(frozen=True, slots=True)
class RedactedArtifact:
    output: Path = field(repr=False)
    receipt: Path = field(repr=False)
    report_output: Path = field(repr=False)
    output_sha256: str
    plan_sha256: str
    edit_count: int


def _new_paths(source: Path, plan: Path, paths: tuple[Path, ...]) -> None:
    try:
        protected = {source.resolve(), plan.resolve()}
        seen: set[Path] = set()
        for path in paths:
            resolved = path.resolve()
            if resolved in protected or resolved in seen or path.exists() or path.is_symlink():
                raise DocumentInputError(
                    "redaction outputs must be distinct new files, never inputs"
                )
            if not path.parent.is_dir():
                raise DocumentInputError("redaction output directory does not exist")
            seen.add(resolved)
    except (OSError, RuntimeError) as exc:
        raise DocumentInputError("redaction output boundary could not be resolved safely") from exc


def _source_still_matches(source: Path, plan: RedactionPlan) -> None:
    current = scan(source, limits=plan.limits)
    if (
        current.target_kind != "file"
        or current.target_sha256 != plan.document["source"]["sha256"]
        or boundary_sha256(source, current) != plan.document["source"]["boundary_sha256"]
        or snapshot_sha256(current, plan.threshold) != plan.document["source"]["snapshot_sha256"]
    ):
        raise DocumentInputError("source changed during redaction; no derivative can be published")


def _check_output(report: ScanReport, expected_sha256: str) -> None:
    if report.target_sha256 != expected_sha256 or report.target_kind != "file":
        raise DocumentInputError("redacted output changed before publication")
    if not report.surfaces or report.has_coverage_gaps or report.findings:
        raise RedactionBlocked(
            "redacted output has findings or incomplete coverage; no derivative published"
        )


def apply_redaction_plan(
    source: Path,
    plan_path: Path,
    output: Path,
    *,
    receipt: Path | None = None,
    report_output: Path | None = None,
    limits: ScanLimits | None = None,
    fail_on: Severity = Severity.HIGH,
) -> RedactedArtifact:
    receipt_path = receipt if receipt is not None else Path(f"{output}.sharelint-redact.json")
    report_path = (
        report_output
        if report_output is not None
        else Path(f"{output}.sharelint-redact.report.json")
    )
    _new_paths(source, plan_path, (output, receipt_path, report_path))
    plan = read_redaction_plan(plan_path)
    if not plan.ready:
        raise RedactionBlocked("redaction plan is blocked; no derivative published")
    effective = limits or ScanLimits()
    if plan.document["tool"]["version"] != __version__:
        raise DocumentInputError("redaction plan producer changed; create and review a new plan")
    if plan.document["policy"] != policy_document(effective, fail_on):
        raise DocumentInputError("redaction plan differs from the explicitly selected policy")
    prepared = _prepare(
        source, output.name, tuple(plan.document["selected_rules"]), effective, fail_on
    )
    original_core = {
        key: value
        for key, value in plan.document.items()
        if key not in {"created_at", "document_sha256"}
    }
    if prepared.core != original_core:
        raise DocumentInputError(
            "source, output name, or edit plan changed; create and review a new plan"
        )
    if prepared.core["status"] != "ready":
        raise RedactionBlocked("redaction no longer passes its complete output policy")
    temporary: Path | None = None
    publications: list[tuple[Path, _PublishedFile]] = []
    try:
        with tempfile.NamedTemporaryFile(
            prefix=".sharelint-redact-", suffix=".tmp", dir=output.parent, delete=False, mode="wb"
        ) as handle:
            temporary = Path(handle.name)
            handle.write(prepared.output_bytes)
            handle.flush()
            os.fsync(handle.fileno())
        output_report = scan(temporary, limits=effective, logical_name=output.name)
        _check_output(output_report, plan.document["output"]["sha256"])
        _source_still_matches(source, plan)
        report_bytes = render_json(output_report, fail_on).encode("utf-8")
        publication = _publish_without_overwrite(
            temporary, output, output_report.target_sha256, len(prepared.output_bytes)
        )
        publications.append((output, publication))
        publications.append(
            (report_path, _write_bytes(report_path, report_bytes, "redaction report"))
        )
        document = {
            "schema_version": "1.0.0",
            "receipt_type": "sharelint.text-redaction",
            "status": "applied",
            "tool": {"name": "sharelint", "version": __version__},
            "created_at": datetime.now(UTC)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
            "source": {key: plan.document["source"][key] for key in ("sha256", "size")},
            "output": {"sha256": output_report.target_sha256, "size": len(prepared.output_bytes)},
            "plan": {"sha256": plan.sha256, "document_sha256": plan.document["document_sha256"]},
            "policy": plan.document["policy"],
            "require_no_findings": True,
            "edit_count": len(plan.document["edits"]),
            "summary": output_report.summary(fail_on),
            "report_sha256": hashlib.sha256(report_bytes).hexdigest(),
            "verification": {
                "source_rechecked": True,
                "reopened_and_rescanned": True,
                "coverage_complete": True,
            },
            "claim": _CLAIM,
        }
        publications.append((receipt_path, _write_document(receipt_path, document)))
        _commit_publications(publications)
    except BaseException as exc:
        for path, publication in reversed(publications):
            _unlink_published(path, publication)
        if isinstance(exc, (OSError, PackError)):
            raise DocumentInputError(
                "redaction publication failed; inspect outputs before retrying"
            ) from exc
        raise
    finally:
        if temporary is not None:
            with suppress(OSError):
                temporary.unlink(missing_ok=True)
    return RedactedArtifact(
        output,
        receipt_path,
        report_path,
        plan.document["output"]["sha256"],
        plan.sha256,
        len(plan.document["edits"]),
    )


@dataclass(frozen=True, slots=True)
class RedactionVerification:
    output_sha256: str
    receipt_sha256: str
    report_sha256: str
    plan_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0.0",
            "verification_type": "sharelint.text-redaction-integrity",
            "status": "verified",
            "output_sha256": self.output_sha256,
            "receipt_sha256": self.receipt_sha256,
            "report_sha256": self.report_sha256,
            "plan_sha256": self.plan_sha256,
            "checks": [
                "receipt-structure",
                "plan-bytes",
                "plan-policy",
                "output-bytes",
                "report-bytes",
                "report-summary",
            ],
            "claim": "Integrity only, not authentication, a new scan, or a safety guarantee. The original source is not supplied or rechecked by this verifier.",
        }


def _matches(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def verify_redaction(
    output: Path,
    receipt_path: Path,
    report_path: Path,
    plan_path: Path,
    *,
    limits: ScanLimits | None = None,
    expected_receipt_sha256: str | None = None,
) -> RedactionVerification:
    effective = limits or ScanLimits()
    receipt_bytes = read_document(receipt_path, MAX_DOCUMENT_BYTES)
    receipt_sha = hashlib.sha256(receipt_bytes).hexdigest()
    if expected_receipt_sha256 is not None:
        _matches(
            receipt_sha == digest(expected_receipt_sha256),
            "receipt differs from the expected digest",
        )
    document = object_fields(
        parse_json(receipt_bytes),
        (
            "schema_version",
            "receipt_type",
            "status",
            "tool",
            "created_at",
            "source",
            "output",
            "plan",
            "policy",
            "require_no_findings",
            "edit_count",
            "summary",
            "report_sha256",
            "verification",
            "claim",
        ),
        strict=True,
    )
    require(
        document["schema_version"] == "1.0.0"
        and document["receipt_type"] == "sharelint.text-redaction"
        and document["status"] == "applied"
    )
    require(document["require_no_findings"] is True)
    tool = object_fields(document["tool"], ("name", "version"), strict=True)
    require(tool["name"] == "sharelint")
    string(tool["version"], maximum=128)
    timestamp = string(document["created_at"], maximum=64)
    require(re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", timestamp) is not None)
    try:
        datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise DocumentInputError("redaction receipt timestamp is invalid") from exc
    string(document["claim"])
    for key in ("source", "output"):
        record = object_fields(document[key], ("sha256", "size"), strict=True)
        digest(record["sha256"])
        require(integer(record["size"]) <= MAX_REDACTION_BYTES)
    binding = object_fields(document["plan"], ("sha256", "document_sha256"), strict=True)
    digest(binding["sha256"])
    digest(binding["document_sha256"])
    verification = object_fields(
        document["verification"],
        ("source_rechecked", "reopened_and_rescanned", "coverage_complete"),
        strict=True,
    )
    require(all(value is True for value in verification.values()))
    plan = read_redaction_plan(plan_path)
    receipt_policy = object_fields(
        document["policy"],
        ("sha256", "ruleset_sha256", "fail_on", "require_complete_coverage", "limits"),
        strict=True,
    )
    validate_limits(receipt_policy["limits"], strict=True)
    require(receipt_policy["require_complete_coverage"] is True)
    digest(receipt_policy["sha256"])
    digest(receipt_policy["ruleset_sha256"])
    _summary(document["summary"], plan.threshold)
    _matches(
        plan.ready
        and plan.sha256 == binding["sha256"]
        and plan.document["document_sha256"] == binding["document_sha256"],
        "redaction plan binding does not match",
    )
    _matches(
        document["policy"] == plan.document["policy"] and tool == plan.document["tool"],
        "redaction policy or producer does not match the plan",
    )
    _matches(
        integer(document["edit_count"]) == len(plan.document["edits"]),
        "redaction edit count does not match the plan",
    )
    for key in ("source", "output"):
        _matches(
            document[key] == {field: plan.document[key][field] for field in ("sha256", "size")},
            "redaction content identity differs from the plan",
        )
    output_bytes = read_document(
        output, min(MAX_REDACTION_BYTES, effective.max_file_bytes, effective.max_total_bytes)
    )
    output_sha = hashlib.sha256(output_bytes).hexdigest()
    _matches(
        output_sha == document["output"]["sha256"]
        and len(output_bytes) == document["output"]["size"],
        "output bytes do not match the receipt",
    )
    report_bytes = read_document(report_path, MAX_DOCUMENT_BYTES)
    report_sha = hashlib.sha256(report_bytes).hexdigest()
    _matches(
        report_sha == digest(document["report_sha256"]), "report bytes do not match the receipt"
    )
    report, threshold = validate_report(report_bytes)
    _matches(
        report.target_kind == "file" and report.target_sha256 == output_sha,
        "report target does not match output bytes",
    )
    _matches(
        bool(report.surfaces) and not report.has_coverage_gaps and not report.findings,
        "redaction output report is not complete and finding-free",
    )
    _matches(
        report.tool_version == tool["version"]
        and report.limits == plan.limits
        and threshold == plan.threshold,
        "report policy does not match the plan",
    )
    _matches(
        document["summary"] == report.summary(threshold),
        "receipt summary does not match the report",
    )
    return RedactionVerification(output_sha, receipt_sha, report_sha, plan.sha256)
