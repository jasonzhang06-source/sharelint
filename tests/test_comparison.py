from __future__ import annotations

import copy
import json
from dataclasses import replace
from pathlib import Path

import tests.bootstrap  # noqa: F401
from sharelint.comparison import compare_reports
from sharelint.input_io import DocumentInputError
from sharelint.models import (
    Finding,
    ScanError,
    ScanLimits,
    ScanReport,
    ScanSurface,
    Severity,
    SurfaceStatus,
)
from sharelint.reporters import render_json
from sharelint.scanner import scan
from tests.cli_harness import CliTestCase


class ComparisonTests(CliTestCase):
    def base_report(self) -> ScanReport:
        return ScanReport(
            "PRIVATE_FILE_NAME.txt",
            "file",
            "a" * 64,
            "a" * 16,
            ScanLimits(),
            surfaces=[
                ScanSurface(("PRIVATE_SOURCE",), "text", SurfaceStatus.SCANNED, 1024, "text")
            ],
        )

    def finding(
        self, severity: Severity = Severity.HIGH, rule_id: str = "SL.OFFICE.NOTES"
    ) -> Finding:
        return Finding(
            rule_id,
            severity,
            "PRIVATE_TITLE",
            ("PRIVATE_SOURCE",),
            "PRIVATE_LOCATION",
            "PRIVATE_PREVIEW",
            "hmac-sha256:" + "1" * 24,
            "PRIVATE_REMEDIATION",
        )

    def write_report(
        self, name: str, report: ScanReport, threshold: Severity = Severity.HIGH
    ) -> Path:
        path = self.root / name
        path.write_text(render_json(report, threshold), encoding="utf-8")
        return path

    def compare(self, before: ScanReport, after: ScanReport):
        return compare_reports(
            self.write_report("before.json", before), self.write_report("after.json", after)
        )

    def test_identical_counts_never_compare_ephemeral_fingerprints(self) -> None:
        before = self.base_report()
        before.findings = [self.finding()]
        after = copy.deepcopy(before)
        after.fingerprint_scope = "b" * 16
        after.findings = [
            replace(before.findings[0], evidence_fingerprint="hmac-sha256:" + "2" * 24)
        ]
        result = self.compare(before, after)
        self.assertFalse(result.requires_review)
        self.assertEqual(result.changes, ())
        self.assertIn("not compared", result.render_console())
        self.assertFalse(result.to_dict()["scope"]["matched_values_compared"])

    def test_increased_blocking_rule_count_requires_review(self) -> None:
        before = self.base_report()
        after = copy.deepcopy(before)
        after.findings = [self.finding()]
        result = self.compare(before, after)
        self.assertEqual(result.decision, "regression-observed")
        self.assertEqual(result.changes[0]["delta"], 1)
        self.assertTrue(result.requires_review)

    def test_nonblocking_increase_is_visible_and_threshold_can_be_explicit(self) -> None:
        before = self.base_report()
        after = copy.deepcopy(before)
        after.findings = [self.finding(Severity.LOW)]
        result = self.compare(before, after)
        self.assertFalse(result.requires_review)
        self.assertEqual(len(result.changes), 1)
        changed = compare_reports(
            self.root / "before.json", self.root / "after.json", fail_on=Severity.LOW
        )
        self.assertTrue(changed.requires_review)

    def test_coverage_regression_never_looks_like_successful_cleanup(self) -> None:
        before = self.base_report()
        before.findings = [self.finding()]
        after = copy.deepcopy(before)
        after.findings.clear()
        after.surfaces[0] = replace(
            after.surfaces[0], status=SurfaceStatus.SKIPPED, bytes_inspected=0
        )
        after.errors = [
            ScanError(("PRIVATE_ERROR_SOURCE",), "SL.SCAN.READ_ERROR", "PRIVATE_ERROR_TEXT")
        ]
        result = self.compare(before, after)
        self.assertEqual(result.decision, "regression-observed")
        self.assertIn("coverage-gaps-increased", result.review_reasons)
        self.assertEqual(result.changes[0]["delta"], -1)

    def test_existing_incomplete_coverage_always_requires_review(self) -> None:
        before = self.base_report()
        before.surfaces[0] = replace(before.surfaces[0], status=SurfaceStatus.PARTIAL)
        result = self.compare(before, copy.deepcopy(before))
        self.assertEqual(result.decision, "review-required")
        self.assertIn("current-coverage-incomplete", result.review_reasons)

    def test_less_inspection_requires_review_even_with_complete_status(self) -> None:
        before = self.base_report()
        before.surfaces.append(replace(before.surfaces[0], kind="metadata"))
        after = copy.deepcopy(before)
        after.surfaces.pop()
        result = self.compare(before, after)
        self.assertIn("surface-count-decreased", result.review_reasons)
        self.assertIn("inspected-byte-count-decreased", result.review_reasons)

    def test_settings_and_target_kind_changes_remain_visible(self) -> None:
        before = self.base_report()
        after = copy.deepcopy(before)
        after.tool_version = "999.0.0"
        after.target_kind = "directory"
        after.limits = ScanLimits(max_file_bytes=1024)
        result = self.compare(before, after)
        self.assertEqual(result.decision, "review-required")
        self.assertIn("producer-version-changed", result.review_reasons)
        self.assertIn("resource-limits-changed", result.review_reasons)
        self.assertIn("target-kind-changed", result.review_reasons)
        self.write_report("before.json", before, Severity.LOW)
        self.write_report("after.json", before, Severity.HIGH)
        result = compare_reports(self.root / "before.json", self.root / "after.json")
        self.assertIn("recorded-threshold-changed", result.review_reasons)
        result = compare_reports(
            self.root / "before.json", self.root / "after.json", fail_on=Severity.HIGH
        )
        self.assertFalse(result.requires_review)

    def test_all_formats_discard_untrusted_descriptive_strings(self) -> None:
        before = self.base_report()
        after = copy.deepcopy(before)
        after.findings = [self.finding(rule_id="SL.PRIVATE_SECRET.PRIVATE_RULE")]
        result = self.compare(before, after)
        for format_name in ("console", "json", "html"):
            rendered = result.render(format_name)
            self.assertNotIn("PRIVATE", rendered)
            self.assertIn("unrecognized-rule", rendered)
            self.assertIn("not a safety verdict", rendered)
        self.assertIn("Content-Security-Policy", result.render_html())
        self.assertNotIn("<script", result.render_html())
        self.assertEqual(
            json.loads(result.render("json"))["comparison_type"], "sharelint.aggregate-diff"
        )
        with self.assertRaises(ValueError):
            result.render("sarif")

    def test_real_scans_compare_without_stable_evidence_hashes(self) -> None:
        source = self.root / "ordinary.txt"
        source.write_text("synthetic public document\n", encoding="utf-8")
        result = self.compare(scan(source), scan(source))
        self.assertFalse(result.requires_review)

    def test_invalid_report_or_empty_coverage_cannot_pass_review(self) -> None:
        before = self.base_report()
        after = copy.deepcopy(before)
        after.surfaces.clear()
        result = self.compare(before, after)
        self.assertTrue(result.requires_review)
        (self.root / "after.json").write_text('{"summary":{"verdict":"pass"}}', encoding="utf-8")
        with self.assertRaises(DocumentInputError):
            compare_reports(self.root / "before.json", self.root / "after.json")

    def test_cli_review_exit_and_no_overwrite_contract(self) -> None:
        before = self.base_report()
        after = copy.deepcopy(before)
        after.findings = [self.finding()]
        self.compare(before, after)
        result = self.run_cli(
            "diff", self.root / "before.json", self.root / "after.json", "--format", "json"
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.json()["decision"], "regression-observed")
        self.assertNotIn("PRIVATE", result.stdout)
        output = self.root / "comparison.html"
        result = self.run_cli(
            "diff",
            self.root / "before.json",
            self.root / "after.json",
            "--format",
            "html",
            "-o",
            output,
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        original = output.read_bytes()
        self.assertIn(b"Content-Security-Policy", original)
        again = self.run_cli(
            "diff",
            self.root / "before.json",
            self.root / "after.json",
            "--format",
            "html",
            "-o",
            output,
        )
        self.assertEqual(again.returncode, 2)
        self.assertEqual(output.read_bytes(), original)
        missing_output = self.run_cli(
            "diff", self.root / "before.json", self.root / "after.json", "--format", "html"
        )
        self.assertEqual(missing_output.returncode, 2)
        same = self.run_cli("diff", self.root / "before.json", self.root / "before.json")
        self.assertEqual(same.returncode, 0, same.stderr)
