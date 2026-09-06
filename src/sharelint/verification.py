"""Offline integrity verification; never authentication or a privacy guarantee."""

from __future__ import annotations

import hashlib
import io
import re
import stat
import zipfile
import zlib
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from .documents import (
    MAX_DOCUMENT_BYTES,
    array,
    choice,
    digest,
    integer,
    object_fields,
    parse_json,
    require,
    string,
    validate_limits,
    validate_report,
    validate_summary,
)
from .input_io import DocumentInputError, read_document
from .models import ScanLimits, Severity
from .planning import read_plan
from .reporters import canonical_json
from .scanners.archive import has_excessive_central_directory, normalized_member_name

_REASONS = (
    "blocking_findings",
    "coverage_incomplete",
    "source_changed",
    "pack_write_failed",
    "artifact_rescan_failed",
    "artifact_manifest_mismatch",
)
_DISCLAIMER = (
    "Integrity only: no signature, producer authentication, new privacy scan, or safety guarantee."
)


class VerificationError(ValueError):
    """Well-formed inputs fail their integrity or policy-consistency checks."""


@dataclass(frozen=True, slots=True)
class VerificationResult:
    status: str
    receipt_sha256: str
    report_sha256: str
    archive_sha256: str | None
    file_count: int
    checks: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0.0",
            "verification_type": "sharelint.integrity",
            "status": self.status,
            "receipt_sha256": self.receipt_sha256,
            "report_sha256": self.report_sha256,
            "archive_sha256": self.archive_sha256,
            "file_count": self.file_count,
            "checks": list(self.checks),
            "claim": _DISCLAIMER,
        }

    def render_console(self) -> str:
        heading = "INTEGRITY VERIFIED" if self.status == "verified" else "BLOCKED RECEIPT VERIFIED"
        return f"{heading}\nChecks: {', '.join(self.checks)}\n{_DISCLAIMER}\n"


def _matches(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def validate_receipt(data: bytes) -> dict[str, Any]:
    doc = object_fields(
        parse_json(data),
        (
            "schema_version",
            "receipt_type",
            "status",
            "tool",
            "created_at",
            "source",
            "policy",
            "summary",
            "report_sha256",
            "reasons",
            "claim",
        ),
        optional=("archive", "files", "verification", "plan"),
        strict=True,
    )
    version = choice(doc["schema_version"], ("1.0.0", "2.0.0"))
    require(doc["receipt_type"] == "sharelint.pack")
    if version == "2.0.0" and "plan" in doc:
        require(doc["status"] == "packed")
        binding = object_fields(
            doc["plan"],
            (
                "schema_version",
                "sha256",
                "snapshot_sha256",
                "source_boundary_sha256",
            ),
            strict=True,
        )
        require(binding["schema_version"] == "1.0.0")
        for key in ("sha256", "snapshot_sha256", "source_boundary_sha256"):
            digest(binding[key])
    elif version == "1.0.0":
        require("plan" not in doc)
    status = choice(doc["status"], ("packed", "blocked"))
    tool = object_fields(doc["tool"], ("name", "version"), strict=True)
    require(tool["name"] == "sharelint")
    string(tool["version"], maximum=128)
    timestamp = string(doc["created_at"], maximum=64)
    require(
        re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})", timestamp
        )
        is not None
    )
    try:
        require(datetime.fromisoformat(timestamp.replace("Z", "+00:00")).tzinfo is not None)
    except ValueError as exc:
        raise DocumentInputError("receipt timestamp is invalid") from exc
    source = object_fields(
        doc["source"], ("kind", "hash_status"), optional=("sha256",), strict=True
    )
    choice(source["kind"], ("file", "directory", "symlink"))
    if choice(source["hash_status"], ("complete", "unavailable")) == "complete":
        require("sha256" in source)
        digest(source["sha256"])
    else:
        require("sha256" not in source)
    policy = object_fields(
        doc["policy"],
        (
            "sha256",
            "ruleset_sha256",
            "fail_on",
            "require_complete_coverage",
            "limits",
        ),
        strict=True,
    )
    digest(policy["sha256"])
    digest(policy["ruleset_sha256"])
    choice(policy["fail_on"], Severity)
    require(policy["require_complete_coverage"] is True)
    validate_limits(policy["limits"], strict=True)
    validate_summary(doc["summary"], strict=True)
    digest(doc["report_sha256"])
    reasons = [choice(reason, _REASONS) for reason in array(doc["reasons"], maximum=len(_REASONS))]
    require(len(set(reasons)) == len(reasons))
    string(doc["claim"])
    if status == "blocked":
        require(bool(reasons) and not {"archive", "files", "verification"} & doc.keys())
        return doc
    require(not reasons and {"archive", "files", "verification"} <= doc.keys())
    require(source["hash_status"] == "complete" and source["kind"] != "symlink")
    archive = object_fields(doc["archive"], ("format", "size", "sha256", "profile"), strict=True)
    require(archive["format"] == "zip" and archive["profile"] == "deterministic-zip-v1")
    integer(archive["size"])
    digest(archive["sha256"])
    names: list[str] = []
    for index, value in enumerate(array(doc["files"])):
        if version == "1.0.0":
            item = object_fields(value, ("path", "size", "sha256"), strict=True)
            name = string(item["path"], maximum=4096)
            require(normalized_member_name(name) == name and not name.endswith("/"))
            names.append(name)
        else:
            item = object_fields(value, ("entry", "size", "sha256"), strict=True)
            require(integer(item["entry"]) == index)
        integer(item["size"])
        digest(item["sha256"])
    require(names == sorted(set(names)))
    verification = object_fields(
        doc["verification"],
        (
            "coverage_complete",
            "reopened_and_rescanned",
            "manifest_matched",
        ),
        strict=True,
    )
    require(all(value is True for value in verification.values()))
    return doc


def _archive_manifest(data: bytes, limits: ScanLimits) -> list[dict[str, Any]]:
    _matches(
        not has_excessive_central_directory(data, limits.max_archive_members),
        "archive exceeds the verifier member limit",
    )
    result: list[dict[str, Any]] = []
    names: list[str] = []
    total = 0
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
            _matches(
                len(infos) <= limits.max_archive_members,
                "archive exceeds the verifier member limit",
            )
            for info in infos:
                name = normalized_member_name(info.filename)
                _matches(
                    name == info.filename == info.orig_filename
                    and bool(name)
                    and not info.is_dir()
                    and not info.flag_bits & 1
                    and stat.S_ISREG(info.external_attr >> 16)
                    and info.compress_type == zipfile.ZIP_DEFLATED,
                    "archive contains an unsupported or unsafe member",
                )
                _matches(
                    info.file_size <= limits.max_member_bytes,
                    "archive exceeds the verifier member byte limit",
                )
                _matches(
                    info.file_size / max(1, info.compress_size) <= limits.max_compression_ratio,
                    "archive exceeds the verifier compression ratio limit",
                )
                names.append(info.filename)
                count = 0
                hasher = hashlib.sha256()
                with archive.open(info) as member:
                    while True:
                        chunk = member.read(min(64 * 1024, limits.max_member_bytes + 1 - count))
                        if not chunk:
                            break
                        count += len(chunk)
                        total += len(chunk)
                        _matches(
                            count <= limits.max_member_bytes and total <= limits.max_total_bytes,
                            "archive exceeds the verifier decompression byte limit",
                        )
                        hasher.update(chunk)
                _matches(count == info.file_size, "archive member size does not match")
                result.append({"path": info.filename, "size": count, "sha256": hasher.hexdigest()})
            _matches(names == sorted(set(names)), "archive members are duplicated or out of order")
    except (
        zipfile.BadZipFile,
        RuntimeError,
        NotImplementedError,
        OSError,
        EOFError,
        ValueError,
        zlib.error,
    ) as exc:
        if isinstance(exc, VerificationError):
            raise
        raise VerificationError("archive could not be verified safely") from exc
    return result


def verify_receipt(
    receipt_path: Path,
    report_path: Path,
    artifact_path: Path | None = None,
    *,
    limits: ScanLimits | None = None,
    expected_receipt_sha256: str | None = None,
    plan_path: Path | None = None,
) -> VerificationResult:
    """Check exact bytes and consistency; never follow paths embedded in inputs.

    Verifier budgets come from the caller, never from an untrusted receipt.
    An optional receipt digest must come from an independently trusted channel.
    """

    limits = limits or ScanLimits()
    if expected_receipt_sha256 is not None:
        digest(expected_receipt_sha256)
    receipt_bytes = read_document(receipt_path, MAX_DOCUMENT_BYTES)
    receipt_hash = hashlib.sha256(receipt_bytes).hexdigest()
    if expected_receipt_sha256 is not None:
        _matches(
            receipt_hash == expected_receipt_sha256, "receipt does not match the expected digest"
        )
    receipt = validate_receipt(receipt_bytes)
    report_bytes = read_document(report_path, MAX_DOCUMENT_BYTES)
    report_hash = hashlib.sha256(report_bytes).hexdigest()
    _matches(report_hash == receipt["report_sha256"], "report bytes do not match the receipt")
    report, threshold = validate_report(report_bytes)
    policy = receipt["policy"]
    descriptor = {
        "format": "sharelint-pack-policy-v1",
        "fail_on": policy["fail_on"],
        "require_complete_coverage": True,
        "limits": policy["limits"],
        "ruleset_sha256": policy["ruleset_sha256"],
    }
    policy_hash = hashlib.sha256(canonical_json(descriptor).encode("utf-8")).hexdigest()
    _matches(policy_hash == policy["sha256"], "policy digest does not match its recorded settings")
    _matches(
        threshold.value == policy["fail_on"]
        and report.limits.to_dict() == policy["limits"]
        and report.tool_version == receipt["tool"]["version"]
        and report.summary(threshold) == receipt["summary"],
        "report and receipt have inconsistent policy or summary fields",
    )
    checks: tuple[str, ...] = (
        "receipt-structure",
        "report-bytes",
        "report-summary",
        "policy-binding",
    )
    if expected_receipt_sha256 is not None:
        checks += ("expected-receipt-digest",)
    if "plan" in receipt:
        if plan_path is None:
            raise DocumentInputError(
                "planned receipt verification requires an explicit --plan file"
            )
        plan = read_plan(plan_path)
        _matches(
            plan.ready
            and plan.binding() == receipt["plan"]
            and plan.document["policy"] == policy
            and plan.report.tool_version == receipt["tool"]["version"]
            and plan.report.target_kind == receipt["source"]["kind"]
            and plan.report.target_sha256 == receipt["source"].get("sha256"),
            "handoff plan does not match the receipt bindings",
        )
        checks += ("handoff-plan-binding",)
    elif plan_path is not None:
        raise DocumentInputError("this receipt has no handoff plan binding")
    if receipt["status"] == "blocked":
        require(artifact_path is None)
        expected_source: dict[str, Any] = {
            "kind": report.target_kind,
            "hash_status": "unavailable" if report.has_coverage_gaps else "complete",
        }
        if not report.has_coverage_gaps:
            expected_source["sha256"] = report.target_sha256
        _matches(
            receipt["source"] == expected_source, "blocked receipt source does not match the report"
        )
        for reason, condition in (
            ("blocking_findings", report.count_at_or_above(threshold) > 0),
            ("coverage_incomplete", report.has_coverage_gaps),
        ):
            _matches(
                (reason in receipt["reasons"]) == condition,
                "blocked receipt reasons do not match the report",
            )
        return VerificationResult("blocked", receipt_hash, report_hash, None, 0, checks)
    if artifact_path is None:
        raise DocumentInputError("packed receipt verification requires an explicit archive path")
    _matches(
        report.summary(threshold)["verdict"] == "pass" and bool(report.surfaces),
        "packed receipt does not have a complete passing report",
    )
    # Read once into bounded memory: hashing and ZIP inspection use identical bytes.
    artifact_bytes = read_document(artifact_path, limits.max_file_bytes)
    artifact_hash = hashlib.sha256(artifact_bytes).hexdigest()
    _matches(
        artifact_hash == receipt["archive"]["sha256"]
        and len(artifact_bytes) == receipt["archive"]["size"],
        "archive bytes do not match the receipt",
    )
    _matches(
        report.target_kind == "file" and report.target_sha256 == artifact_hash,
        "report target does not match the archive",
    )
    manifest = _archive_manifest(artifact_bytes, limits)
    if receipt["schema_version"] == "2.0.0":
        manifest = [
            {"entry": index, "size": item["size"], "sha256": item["sha256"]}
            for index, item in enumerate(manifest)
        ]
    _matches(manifest == receipt["files"], "archive contents do not match the recorded manifest")
    return VerificationResult(
        "verified",
        receipt_hash,
        report_hash,
        artifact_hash,
        len(manifest),
        checks + ("archive-bytes", "report-target", "file-manifest"),
    )
