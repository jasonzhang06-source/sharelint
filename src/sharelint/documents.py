"""Bounded parsing and semantic validation of untrusted native JSON reports.

Validation does not authenticate a producer or prove that strings were masked.
Consumers must not display imported evidence, paths, or explanatory strings.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Iterable
from typing import Any

from .input_io import DocumentInputError
from .models import Finding, ScanError, ScanLimits, ScanReport, ScanSurface, Severity, SurfaceStatus

MAX_DOCUMENT_BYTES = 16 * 1024 * 1024
MAX_DOCUMENT_NODES = 500_000
MAX_DOCUMENT_DEPTH = 32
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
RULE_ID = re.compile(r"SL\.[A-Z][A-Z0-9_]*\.[A-Z][A-Z0-9_]*\Z")


def require(condition: bool) -> None:
    if not condition:
        raise DocumentInputError("document has an unsupported or inconsistent structure")


def object_fields(
    value: Any, required: Iterable[str], *, optional: Iterable[str] = (), strict: bool = False
) -> dict[str, Any]:
    require(isinstance(value, dict))
    keys = set(required)
    require(keys <= value.keys())
    if strict:
        require(value.keys() <= keys | set(optional))
    return dict(value)


def string(value: Any, *, minimum: int = 1, maximum: int = 262_144) -> str:
    require(isinstance(value, str))
    require(minimum <= len(value) <= maximum)
    require(not any(0xD800 <= ord(character) <= 0xDFFF for character in value))
    return str(value)


def integer(value: Any, *, minimum: int = 0) -> int:
    require(type(value) is int and minimum <= value <= 2**63 - 1)
    return int(value)


def array(value: Any, *, maximum: int = 100_000) -> list[Any]:
    require(isinstance(value, list) and len(value) <= maximum)
    return list(value)


def digest(value: Any) -> str:
    result = string(value, maximum=64)
    require(SHA256.fullmatch(result) is not None)
    return result


def choice(value: Any, choices: Iterable[str]) -> str:
    result = string(value)
    # EnumType.__contains__ rejects plain strings on Python 3.11. Iterate
    # values explicitly so validation behaves identically on every runtime.
    require(any(result == candidate for candidate in choices))
    return result


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise DocumentInputError("non-finite JSON values are not supported")


def parse_json(data: bytes) -> dict[str, Any]:
    require(len(data) <= MAX_DOCUMENT_BYTES)
    try:
        # Bound syntactic nesting before asking the recursive JSON decoder to parse.
        text = data.decode("utf-8")
        depth = 0
        quoted = escaped = False
        for character in text:
            if quoted:
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == '"':
                    quoted = False
            elif character == '"':
                quoted = True
            elif character in "[{":
                depth += 1
                require(depth <= MAX_DOCUMENT_DEPTH)
            elif character in "]}":
                depth -= 1
        value = json.loads(text, object_pairs_hook=_pairs, parse_constant=_reject_constant)
        pending = [value]
        count = 0
        while pending:
            node = pending.pop()
            count += 1
            require(count <= MAX_DOCUMENT_NODES)
            if isinstance(node, dict):
                pending.extend(node.keys())
                pending.extend(node.values())
            elif isinstance(node, list):
                pending.extend(node)
            elif isinstance(node, str):
                string(node, minimum=0)
            elif type(node) is float:
                require(math.isfinite(node))
        return object_fields(value, ())
    except (UnicodeError, ValueError, RecursionError, OverflowError) as exc:
        raise DocumentInputError("JSON document is invalid or exceeds validation limits") from exc


def validate_limits(value: Any, *, strict: bool = False) -> ScanLimits:
    fields = ScanLimits().to_dict()
    document = object_fields(value, fields, strict=strict)
    values = {key: document[key] for key in fields}
    for key, item in values.items():
        if key != "max_compression_ratio":
            integer(item, minimum=1)
    try:
        return ScanLimits(**values)
    except (TypeError, ValueError, OverflowError) as exc:
        raise DocumentInputError("document contains invalid resource limits") from exc


def validate_summary(value: Any, *, strict: bool = False) -> dict[str, Any]:
    fields = (
        "verdict",
        "fail_on",
        "blocking_findings",
        "total_findings",
        "findings_by_severity",
        "surface_count",
        "surfaces_by_status",
        "bytes_inspected",
        "error_count",
        "coverage_complete",
    )
    doc = object_fields(value, fields, strict=strict)
    result: dict[str, Any] = {
        "verdict": choice(doc["verdict"], ("pass", "blocked", "incomplete")),
        "fail_on": choice(doc["fail_on"], Severity),
        "coverage_complete": doc["coverage_complete"],
    }
    require(type(result["coverage_complete"]) is bool)
    for key in (
        "blocking_findings",
        "total_findings",
        "surface_count",
        "bytes_inspected",
        "error_count",
    ):
        result[key] = integer(doc[key])
    for key, names in (
        ("findings_by_severity", [item.value for item in Severity]),
        ("surfaces_by_status", [item.value for item in SurfaceStatus]),
    ):
        counts = object_fields(doc[key], names, strict=strict)
        for item in counts.values():
            integer(item)
        # Unknown nonzero counters cannot be discarded as complete coverage.
        require(all(item == 0 for name, item in counts.items() if name not in names))
        result[key] = {name: counts[name] for name in names}
    return result


def _chain(value: Any) -> tuple[str, ...]:
    entries = array(value, maximum=64)
    require(bool(entries))
    return tuple(string(item, maximum=4096) for item in entries)


def _rule_id(value: Any) -> str:
    result = string(value, maximum=256)
    require(RULE_ID.fullmatch(result) is not None)
    return result


def validate_report(data: bytes) -> tuple[ScanReport, Severity]:
    document = object_fields(
        parse_json(data),
        ("schema_version", "tool", "scan", "summary", "findings", "surfaces", "errors"),
    )
    version = string(document["schema_version"], maximum=64)
    require(re.fullmatch(r"1\.[0-9]+\.[0-9]+", version) is not None)
    tool = object_fields(document["tool"], ("name", "version"))
    require(tool["name"] == "sharelint")
    scan = object_fields(document["scan"], ("target", "fingerprint_scope", "limits"))
    target = object_fields(scan["target"], ("name", "kind", "sha256"))
    scope = string(scan["fingerprint_scope"], maximum=16)
    require(re.fullmatch(r"[0-9a-f]{16}", scope) is not None)
    report = ScanReport(
        target_name=string(target["name"], maximum=4096),
        target_kind=choice(target["kind"], ("file", "directory", "symlink")),
        target_sha256=digest(target["sha256"]),
        fingerprint_scope=scope,
        limits=validate_limits(scan["limits"]),
        tool_version=string(tool["version"], maximum=128),
        schema_version=version,
    )
    for value in array(document["findings"]):
        item = object_fields(
            value,
            (
                "rule_id",
                "severity",
                "title",
                "source_chain",
                "location",
                "masked_preview",
                "evidence_fingerprint",
                "remediation",
                "tags",
            ),
        )
        fingerprint = string(item["evidence_fingerprint"], maximum=36)
        require(re.fullmatch(r"hmac-sha256:[0-9a-f]{24}", fingerprint) is not None)
        report.findings.append(
            Finding(
                rule_id=_rule_id(item["rule_id"]),
                severity=Severity(choice(item["severity"], Severity)),
                title=string(item["title"]),
                source_chain=_chain(item["source_chain"]),
                location=string(item["location"]),
                masked_preview=string(item["masked_preview"], maximum=1024),
                evidence_fingerprint=fingerprint,
                remediation=string(item["remediation"]),
                tags=tuple(string(tag) for tag in array(item["tags"], maximum=256)),
            )
        )
    for value in array(document["surfaces"]):
        item = object_fields(
            value, ("source_chain", "kind", "status", "bytes_inspected", "scanner")
        )
        report.surfaces.append(
            ScanSurface(
                source_chain=_chain(item["source_chain"]),
                kind=string(item["kind"]),
                status=SurfaceStatus(choice(item["status"], SurfaceStatus)),
                bytes_inspected=integer(item["bytes_inspected"]),
                scanner=string(item["scanner"]),
                note=string(item.get("note", ""), minimum=0),
            )
        )
    for value in array(document["errors"]):
        item = object_fields(value, ("source_chain", "code", "message"))
        report.errors.append(
            ScanError(
                source_chain=_chain(item["source_chain"]),
                code=_rule_id(item["code"]),
                message=string(item["message"], maximum=240),
            )
        )
    summary = validate_summary(document["summary"])
    threshold = Severity(summary["fail_on"])
    require(summary == report.summary(threshold))
    return report, threshold
