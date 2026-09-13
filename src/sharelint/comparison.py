"""Compare validated report counts without exposing imported evidence or names."""

from __future__ import annotations

import hashlib
import html
import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .documents import MAX_DOCUMENT_BYTES, validate_report
from .input_io import read_document
from .models import ScanReport, Severity, SurfaceStatus
from .rules import RULES

_CLAIM = (
    "Aggregate counts only. Unchanged counts do not prove unchanged evidence or coverage. "
    "Report-scoped evidence fingerprints are not compared; this is not a safety verdict."
)


@dataclass(frozen=True, slots=True)
class ReportComparison:
    decision: str
    before_sha256: str
    after_sha256: str
    threshold: Severity
    before_summary: dict[str, Any]
    after_summary: dict[str, Any]
    changes: tuple[dict[str, Any], ...]
    review_reasons: tuple[str, ...]

    @property
    def requires_review(self) -> bool:
        return self.decision != "no-regression-observed"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0.0",
            "comparison_type": "sharelint.aggregate-diff",
            "decision": self.decision,
            "before_sha256": self.before_sha256,
            "after_sha256": self.after_sha256,
            "fail_on": self.threshold.value,
            "before": self.before_summary,
            "after": self.after_summary,
            "changes": list(self.changes),
            "review_reasons": list(self.review_reasons),
            "scope": {
                "method": "rule-severity-counts",
                "matched_values_compared": False,
                "filenames_compared": False,
            },
            "claim": _CLAIM,
        }

    def render_console(self) -> str:
        lines = [self.decision.upper().replace("-", " ")]
        for item in self.changes:
            lines.append(
                f"{item['rule_id']} [{item['severity']}] "
                f"{item['before']} -> {item['after']} ({item['delta']:+d})"
            )
        if not self.changes:
            lines.append("No rule/severity count changes.")
        if self.review_reasons:
            lines.append("Review: " + ", ".join(self.review_reasons))
        lines.append(_CLAIM)
        return "\n".join(lines) + "\n"

    def render_html(self) -> str:
        # All report-origin descriptive strings were discarded before rendering.
        rows = "".join(
            "<tr>"
            + "".join(
                f"<td>{html.escape(str(item[key]))}</td>"
                for key in ("rule_id", "severity", "before", "after", "delta")
            )
            + "</tr>"
            for item in self.changes
        )
        reasons = "".join(f"<li>{html.escape(reason)}</li>" for reason in self.review_reasons)
        decision = html.escape(self.decision.replace("-", " ").upper())
        return (
            '<!doctype html><html lang="en"><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">"
            "<title>ShareLint report comparison</title><style>"
            "body{font:16px system-ui;margin:2rem auto;padding:0 1rem;max-width:70rem;background:#101923;color:#e3f2ee}"
            "table{border-collapse:collapse;width:100%}td,th{padding:.65rem;text-align:left;border-bottom:1px solid #3c505b}"
            "h1{color:#56dec0}p{line-height:1.6}code{overflow-wrap:anywhere}"
            "</style><h1>ShareLint report comparison</h1>"
            f"<h2>{decision}</h2><p>{html.escape(_CLAIM)}</p>"
            "<table><thead><tr><th>Rule</th><th>Severity</th><th>Before</th><th>After</th><th>Delta</th>"
            f"</tr></thead><tbody>{rows}</tbody></table><ul>{reasons}</ul>"
            f"<p>Before report: <code>{self.before_sha256}</code><br>"
            f"After report: <code>{self.after_sha256}</code></p></html>\n"
        )

    def render(self, format_name: str) -> str:
        if format_name == "json":
            return json.dumps(self.to_dict(), ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        if format_name == "html":
            return self.render_html()
        if format_name == "console":
            return self.render_console()
        raise ValueError("comparison format must be console, json, or html")


def _counts(report: ScanReport) -> Counter[tuple[str, Severity]]:
    # Unknown identifiers can themselves contain sensitive text. Keep their
    # severities/counts but group them under a fixed label instead of echoing them.
    return Counter(
        (finding.rule_id if finding.rule_id in RULES else "unrecognized-rule", finding.severity)
        for finding in report.findings
    )


def compare_reports(
    before_path: Path, after_path: Path, *, fail_on: Severity | None = None
) -> ReportComparison:
    before_bytes = read_document(before_path, MAX_DOCUMENT_BYTES)
    after_bytes = read_document(after_path, MAX_DOCUMENT_BYTES)
    before, before_threshold = validate_report(before_bytes)
    after, after_threshold = validate_report(after_bytes)
    threshold = fail_on or after_threshold
    old_counts, new_counts = _counts(before), _counts(after)
    keys = sorted(old_counts.keys() | new_counts.keys(), key=lambda key: (key[0], key[1].rank))
    changes: tuple[dict[str, Any], ...] = tuple(
        {
            "rule_id": rule,
            "severity": severity.value,
            "before": old_counts[rule, severity],
            "after": new_counts[rule, severity],
            "delta": new_counts[rule, severity] - old_counts[rule, severity],
        }
        for rule, severity in keys
        if old_counts[rule, severity] != new_counts[rule, severity]
    )
    reasons: list[str] = []
    if before.tool_version != after.tool_version:
        reasons.append("producer-version-changed")
    if before.limits != after.limits:
        reasons.append("resource-limits-changed")
    if before_threshold != after_threshold and fail_on is None:
        reasons.append("recorded-threshold-changed")
    if before.target_kind != after.target_kind:
        reasons.append("target-kind-changed")
    old_summary, new_summary = before.summary(threshold), after.summary(threshold)
    if after.has_coverage_gaps:
        reasons.append("current-coverage-incomplete")
    if not after.surfaces or not before.surfaces:
        reasons.append("empty-surface-records")
    if len(after.surfaces) < len(before.surfaces):
        reasons.append("surface-count-decreased")
    if new_summary["bytes_inspected"] < old_summary["bytes_inspected"]:
        reasons.append("inspected-byte-count-decreased")
    if any(rule == "unrecognized-rule" for rule, _ in keys):
        reasons.append("unrecognized-rules-grouped")
    regressions = any(
        item["delta"] > 0 and Severity(item["severity"]).rank >= threshold.rank for item in changes
    )
    old_gaps = sum(surface.status != SurfaceStatus.SCANNED for surface in before.surfaces)
    new_gaps = sum(surface.status != SurfaceStatus.SCANNED for surface in after.surfaces)
    coverage_regressed = (
        (after.has_coverage_gaps and not before.has_coverage_gaps)
        or new_gaps > old_gaps
        or len(after.errors) > len(before.errors)
    )
    if regressions:
        reasons.append("blocking-rule-count-increased")
    if coverage_regressed:
        reasons.append("coverage-gaps-increased")
    decision = (
        "regression-observed"
        if regressions or coverage_regressed
        else "review-required"
        if reasons
        else "no-regression-observed"
    )
    return ReportComparison(
        decision,
        hashlib.sha256(before_bytes).hexdigest(),
        hashlib.sha256(after_bytes).hexdigest(),
        threshold,
        old_summary,
        new_summary,
        changes,
        tuple(reasons),
    )
