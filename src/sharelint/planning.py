"""Reviewable input/policy snapshots; a plan never bypasses fresh pack checks."""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ._version import __version__
from .documents import (
    MAX_DOCUMENT_BYTES,
    choice,
    digest,
    object_fields,
    parse_json,
    require,
    string,
    validate_limits,
    validate_report,
)
from .input_io import DocumentInputError, read_document
from .models import ScanLimits, ScanReport, Severity
from .policy import policy_document
from .reporters import canonical_json
from .scanner import scan


def _sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def boundary_sha256(source: Path, report: ScanReport) -> str:
    """Bind the selected basename, kind, and content identity, not an absolute path."""

    name = os.fsencode(source.name or "share-boundary")
    return hashlib.sha256(
        b"sharelint-source-boundary-v1\0"
        + name
        + b"\0"
        + report.target_kind.encode("ascii")
        + b"\0"
        + report.target_sha256.encode("ascii")
    ).hexdigest()


def snapshot_sha256(report: ScanReport, threshold: Severity) -> str:
    """Fingerprint already-masked report structure without ephemeral value HMACs."""

    document = report.to_dict(threshold)
    document["scan"].pop("fingerprint_scope")
    for finding in document["findings"]:
        finding.pop("evidence_fingerprint")
    return _sha256({"format": "sharelint-review-snapshot-v1", "report": document})


@dataclass(frozen=True, slots=True)
class HandoffPlan:
    payload: bytes = field(repr=False)
    document: dict[str, Any] = field(repr=False)
    report: ScanReport = field(repr=False)
    threshold: Severity

    @property
    def ready(self) -> bool:
        return bool(self.document["status"] == "ready")

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.payload).hexdigest()

    def binding(self) -> dict[str, str]:
        return {
            "schema_version": "1.0.0",
            "sha256": self.sha256,
            "snapshot_sha256": self.document["snapshot_sha256"],
            "source_boundary_sha256": self.document["source"]["boundary_sha256"],
        }

    def summary(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0.0",
            "plan_type": "sharelint.handoff-plan-summary",
            "status": self.document["status"],
            "sha256": self.sha256,
            "snapshot_sha256": self.document["snapshot_sha256"],
            "policy_sha256": self.document["policy"]["sha256"],
            "producer_version_matches": self.report.tool_version == __version__,
            "summary": self.report.summary(self.threshold),
            "claim": "A review snapshot, not approval or a signature. Fresh strict packing checks are still required.",
        }

    def require_match(self, source: Path, report: ScanReport, threshold: Severity) -> None:
        if not self.ready:
            raise DocumentInputError(
                "handoff plan is blocked; resolve findings and coverage before creating a new plan"
            )
        if self.report.tool_version != report.tool_version:
            raise DocumentInputError(
                "handoff plan producer version changed; create and review a new plan"
            )
        if self.document["policy"] != policy_document(report.limits, threshold):
            raise DocumentInputError("handoff plan policy differs from the effective pack policy")
        if self.document["source"]["boundary_sha256"] != boundary_sha256(source, report):
            raise DocumentInputError(
                "handoff source changed since the plan; create and review a new plan"
            )
        if self.document["snapshot_sha256"] != snapshot_sha256(report, threshold):
            raise DocumentInputError(
                "handoff scan results changed since the plan; create and review a new plan"
            )


def validate_plan(data: bytes) -> HandoffPlan:
    doc = object_fields(
        parse_json(data),
        (
            "schema_version",
            "plan_type",
            "status",
            "created_at",
            "source",
            "policy",
            "snapshot_sha256",
            "document_sha256",
            "report",
        ),
        strict=True,
    )
    require(doc["schema_version"] == "1.0.0" and doc["plan_type"] == "sharelint.handoff-plan")
    status = choice(doc["status"], ("ready", "blocked"))
    timestamp = string(doc["created_at"], maximum=64)
    require(re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z", timestamp) is not None)
    try:
        require(
            timestamp.endswith("Z")
            and datetime.fromisoformat(timestamp.replace("Z", "+00:00")).tzinfo is not None
        )
    except ValueError as exc:
        raise DocumentInputError("handoff plan timestamp is invalid") from exc
    report, threshold = validate_report(canonical_json(doc["report"]).encode("utf-8"))
    source = object_fields(doc["source"], ("kind", "sha256", "boundary_sha256"), strict=True)
    require(
        source["kind"] == report.target_kind and digest(source["sha256"]) == report.target_sha256
    )
    digest(source["boundary_sha256"])
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
    ruleset = digest(policy["ruleset_sha256"])
    digest(policy["sha256"])
    validate_limits(policy["limits"], strict=True)
    require(policy["require_complete_coverage"] is True)
    require(policy == policy_document(report.limits, threshold, ruleset_digest=ruleset))
    require(digest(doc["snapshot_sha256"]) == snapshot_sha256(report, threshold))
    ready = (
        bool(report.surfaces)
        and report.target_kind != "symlink"
        and report.summary(threshold)["verdict"] == "pass"
    )
    require((status == "ready") == ready)
    checksum = digest(doc["document_sha256"])
    require(
        checksum == _sha256({key: value for key, value in doc.items() if key != "document_sha256"})
    )
    return HandoffPlan(data, doc, report, threshold)


def read_plan(path: Path) -> HandoffPlan:
    return validate_plan(read_document(path, MAX_DOCUMENT_BYTES))


def create_plan(
    target: Path, *, limits: ScanLimits | None = None, fail_on: Severity = Severity.HIGH
) -> HandoffPlan:
    report = scan(target, limits=limits)
    ready = bool(report.surfaces) and report.summary(fail_on)["verdict"] == "pass"
    doc = {
        "schema_version": "1.0.0",
        "plan_type": "sharelint.handoff-plan",
        "status": "ready" if ready else "blocked",
        "created_at": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "source": {
            "kind": report.target_kind,
            "sha256": report.target_sha256,
            "boundary_sha256": boundary_sha256(target, report),
        },
        "policy": policy_document(report.limits, fail_on),
        "snapshot_sha256": snapshot_sha256(report, fail_on),
        "report": report.to_dict(fail_on),
    }
    doc["document_sha256"] = _sha256(doc)
    data = (json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    return validate_plan(data)
