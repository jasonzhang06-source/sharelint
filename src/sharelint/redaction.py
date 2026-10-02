"""Reviewable text-redaction plans, with masked scans and no embedded source bytes."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ._version import __version__
from .context import ScanContext
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
    validate_summary,
)
from .input_io import DocumentInputError, read_document
from .models import ScanLimits, ScanReport, Severity
from .planning import boundary_sha256, snapshot_sha256
from .policy import policy_document
from .reporters import canonical_json
from .scanner import scan, scan_blob
from .scanners.detect import detect_kind
from .scanners.path import scan_name
from .text_edits import (
    MAX_EDITS,
    MAX_REDACTION_BYTES,
    apply_edits,
    decode_redaction_text,
    plan_edits,
    selected_rules,
    validate_edits,
)

_REASONS = (
    "source-coverage-gap",
    "output-coverage-gap",
    "output-findings-remain",
    "private-key-redaction-unsupported",
)
_CLAIM = (
    "A proposed UTF-8 text derivative, not approval or a safety guarantee. "
    "Originals are never overwritten; application requires fresh source and output checks."
)


class RedactionBlocked(RuntimeError):
    """No derivative was published because the complete redaction policy did not pass."""


def _hash(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def validate_output_name(name: str) -> str:
    name = string(name, maximum=128)
    if (
        name in {".", ".."}
        or name[-1] in ". "
        or any(character in '<>:"/\\|?*' or ord(character) < 32 for character in name)
        or re.fullmatch(r"(?i)(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])", name.split(".")[0])
    ):
        raise DocumentInputError("redaction output name must be a portable filename, not a path")
    return name


def _virtual_report(name: str, data: bytes, limits: ScanLimits) -> ScanReport:
    context = ScanContext(limits)
    display = context.display_path(name)
    scan_name(name, (display,), context)
    scan_blob(name, data, (display,), context)
    context.findings.sort(
        key=lambda item: (-item.severity.rank, item.source_chain, item.location, item.rule_id)
    )
    context.surfaces.sort(key=lambda item: (item.source_chain, item.kind, item.scanner))
    context.errors.sort(key=lambda item: (item.source_chain, item.code))
    return ScanReport(
        display,
        "file",
        hashlib.sha256(data).hexdigest(),
        context.protector.scope,
        limits,
        context.findings,
        context.surfaces,
        context.errors,
    )


def _summary(value: Any, threshold: Severity) -> dict[str, Any]:
    summary = validate_summary(value, strict=True)
    require(summary["fail_on"] == threshold.value)
    require(summary["total_findings"] == sum(summary["findings_by_severity"].values()))
    require(
        summary["blocking_findings"]
        == sum(
            count
            for severity, count in summary["findings_by_severity"].items()
            if Severity(severity).rank >= threshold.rank
        )
    )
    require(summary["surface_count"] == sum(summary["surfaces_by_status"].values()))
    complete = (
        not summary["error_count"]
        and not summary["surfaces_by_status"]["partial"]
        and not summary["surfaces_by_status"]["skipped"]
    )
    require(summary["coverage_complete"] == complete)
    verdict = (
        "incomplete" if not complete else "blocked" if summary["blocking_findings"] else "pass"
    )
    require(summary["verdict"] == verdict)
    return summary


def _reasons(source: dict[str, Any], output: dict[str, Any], private_key: bool) -> list[str]:
    reasons: list[str] = []
    if not source["coverage_complete"] or not source["surface_count"]:
        reasons.append("source-coverage-gap")
    if not output["coverage_complete"] or not output["surface_count"]:
        reasons.append("output-coverage-gap")
    if output["total_findings"]:
        reasons.append("output-findings-remain")
    if private_key:
        reasons.append("private-key-redaction-unsupported")
    return reasons


@dataclass(frozen=True, slots=True)
class RedactionPlan:
    payload: bytes = field(repr=False)
    document: dict[str, Any] = field(repr=False)
    limits: ScanLimits
    threshold: Severity

    @property
    def ready(self) -> bool:
        return bool(self.document["status"] == "ready")

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.payload).hexdigest()

    def summary(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0.0",
            "plan_type": "sharelint.text-redaction-summary",
            "status": self.document["status"],
            "sha256": self.sha256,
            "producer_version_matches": self.document["tool"]["version"] == __version__,
            "source": self.document["source"]["summary"],
            "output": self.document["output"]["summary"],
            "edit_count": len(self.document["edits"]),
            "edits": self.document["edits"],
            "reasons": self.document["reasons"],
            "claim": _CLAIM,
        }


@dataclass(frozen=True, slots=True)
class _Prepared:
    core: dict[str, Any] = field(repr=False)
    output_bytes: bytes = field(repr=False)
    source_report: ScanReport = field(repr=False)


def _prepare(
    source: Path, output_name: str, rules: tuple[str, ...], limits: ScanLimits, threshold: Severity
) -> _Prepared:
    name = validate_output_name(output_name)
    read_limit = min(MAX_REDACTION_BYTES, limits.max_file_bytes, limits.max_total_bytes)
    data = read_document(source, read_limit)
    text = decode_redaction_text(data, limits.max_text_chars)
    if detect_kind(source.name, data) != "text":
        raise DocumentInputError("redaction supports plain text, not document containers or images")
    source_report = scan(source, limits=limits)
    if (
        source_report.target_kind != "file"
        or source_report.target_sha256 != hashlib.sha256(data).hexdigest()
    ):
        raise DocumentInputError("source changed before redaction planning completed")
    maximum = min(MAX_EDITS, limits.max_findings)
    edits = plan_edits(text, rules, maximum=maximum)
    output_bytes = apply_edits(text, edits)
    if len(output_bytes) > read_limit:
        raise DocumentInputError("redacted output exceeds the effective file or scan byte limit")
    if detect_kind(name, output_bytes) != "text":
        raise DocumentInputError("redaction output must remain plain text")
    output_report = _virtual_report(name, output_bytes, limits)
    source_summary, output_summary = (
        source_report.summary(threshold),
        output_report.summary(threshold),
    )
    private_key = any(
        finding.rule_id == "SL.SECRET.PRIVATE_KEY" for finding in source_report.findings
    )
    reasons = _reasons(source_summary, output_summary, private_key)
    core = {
        "schema_version": "1.0.0",
        "plan_type": "sharelint.text-redaction-plan",
        "tool": {"name": "sharelint", "version": __version__},
        "transform": "utf8-span-redaction-v1",
        "require_no_findings": True,
        "status": "blocked" if reasons else "ready",
        "policy": policy_document(limits, threshold),
        "selected_rules": list(rules),
        "source": {
            "sha256": source_report.target_sha256,
            "size": len(data),
            "characters": len(text),
            "boundary_sha256": boundary_sha256(source, source_report),
            "snapshot_sha256": snapshot_sha256(source_report, threshold),
            "summary": source_summary,
        },
        "output": {
            "sha256": output_report.target_sha256,
            "size": len(output_bytes),
            "boundary_sha256": boundary_sha256(Path(name), output_report),
            "snapshot_sha256": snapshot_sha256(output_report, threshold),
            "summary": output_summary,
        },
        "edits": edits,
        "unsupported_private_key": private_key,
        "reasons": reasons,
    }
    return _Prepared(core, output_bytes, source_report)


def validate_redaction_plan(data: bytes) -> RedactionPlan:
    document = object_fields(
        parse_json(data),
        (
            "schema_version",
            "plan_type",
            "tool",
            "transform",
            "require_no_findings",
            "status",
            "policy",
            "selected_rules",
            "source",
            "output",
            "edits",
            "unsupported_private_key",
            "reasons",
            "created_at",
            "document_sha256",
        ),
        strict=True,
    )
    require(
        document["schema_version"] == "1.0.0"
        and document["plan_type"] == "sharelint.text-redaction-plan"
    )
    require(document["transform"] == "utf8-span-redaction-v1")
    require(document["require_no_findings"] is True)
    status = choice(document["status"], ("ready", "blocked"))
    tool = object_fields(document["tool"], ("name", "version"), strict=True)
    require(tool["name"] == "sharelint")
    string(tool["version"], maximum=128)
    timestamp = string(document["created_at"], maximum=64)
    require(re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", timestamp) is not None)
    try:
        datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise DocumentInputError("redaction plan timestamp is invalid") from exc
    policy = object_fields(
        document["policy"],
        ("sha256", "ruleset_sha256", "fail_on", "require_complete_coverage", "limits"),
        strict=True,
    )
    limits = validate_limits(policy["limits"], strict=True)
    threshold = Severity(choice(policy["fail_on"], Severity))
    require(
        policy
        == policy_document(limits, threshold, ruleset_digest=digest(policy["ruleset_sha256"]))
    )
    rules = selected_rules(array(document["selected_rules"], maximum=8))
    require(list(rules) == document["selected_rules"])
    for key in ("source", "output"):
        fields = ("sha256", "size", "boundary_sha256", "snapshot_sha256", "summary")
        record = object_fields(
            document[key], (*fields, "characters") if key == "source" else fields, strict=True
        )
        for name in ("sha256", "boundary_sha256", "snapshot_sha256"):
            digest(record[name])
        require(
            integer(record["size"])
            <= min(MAX_REDACTION_BYTES, limits.max_file_bytes, limits.max_total_bytes)
        )
        _summary(record["summary"], threshold)
    characters = integer(document["source"]["characters"])
    require(characters <= min(document["source"]["size"], limits.max_text_chars))
    validate_edits(
        document["edits"],
        characters=characters,
        rules=rules,
        maximum=min(MAX_EDITS, limits.max_findings),
    )
    require(type(document["unsupported_private_key"]) is bool)
    reasons = [choice(reason, _REASONS) for reason in array(document["reasons"], maximum=4)]
    require(
        reasons
        == _reasons(
            document["source"]["summary"],
            document["output"]["summary"],
            document["unsupported_private_key"],
        )
    )
    require((status == "ready") == (not reasons))
    require(
        digest(document["document_sha256"])
        == _hash({key: value for key, value in document.items() if key != "document_sha256"})
    )
    return RedactionPlan(data, document, limits, threshold)


def read_redaction_plan(path: Path) -> RedactionPlan:
    return validate_redaction_plan(read_document(path, MAX_DOCUMENT_BYTES))


def create_redaction_plan(
    target: Path,
    *,
    output_name: str = "redacted.txt",
    rules: Iterable[str] | None = None,
    limits: ScanLimits | None = None,
    fail_on: Severity = Severity.HIGH,
) -> RedactionPlan:
    prepared = _prepare(target, output_name, selected_rules(rules), limits or ScanLimits(), fail_on)
    document = {
        **prepared.core,
        "created_at": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    }
    document["document_sha256"] = _hash(document)
    payload = (json.dumps(document, sort_keys=True, indent=2) + "\n").encode("utf-8")
    return validate_redaction_plan(payload)
