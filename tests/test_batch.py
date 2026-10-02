from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path
from unittest import mock

import tests.bootstrap  # noqa: F401
from sharelint.batch import (
    BatchLimits,
    BatchResult,
    read_batch_manifest,
    resolve_targets,
    scan_batch,
)
from sharelint.context import ScanContext
from sharelint.input_io import DocumentInputError
from sharelint.models import ScanLimits, ScanReport, Severity
from sharelint.scanner import _scan_with_context
from tests.cli_harness import CliTestCase
from tests.helpers import FICTIONAL_SECRET


class BatchTests(CliTestCase):
    def source(
        self, name: str = "ordinary.txt", content: str = "ordinary synthetic text\n"
    ) -> Path:
        path = self.root / name
        path.write_text(content, encoding="utf-8")
        return path

    def test_multiple_targets_keep_order_and_exact_charged_usage(self) -> None:
        first = self.source("first.txt", "ordinary text")
        second = self.source("second.txt", "another text")
        result = scan_batch((first, second))
        self.assertEqual(result.exit_code, 0)
        document = result.to_dict()
        self.assertEqual([entry.target_id for entry in result.entries], ["t0001", "t0002"])
        self.assertEqual(
            document["summary"]["charged_bytes"], first.stat().st_size + second.stat().st_size
        )
        self.assertTrue(document["summary"]["coverage_complete"])
        self.assertEqual(document["summary"]["targets_by_status"]["pass"], 2)

    def test_blocked_incomplete_and_missing_inputs_never_disappear(self) -> None:
        clean = self.source()
        blocked = self.source("blocked.txt", FICTIONAL_SECRET)
        incomplete = self.source("document.pdf", "%PDF-1.4\n%%EOF")
        absent = self.root / "PRIVATE_MARKER.txt"
        result = scan_batch((clean, blocked, incomplete, absent))
        self.assertEqual(
            [entry.status for entry in result.entries], ["pass", "blocked", "incomplete", "error"]
        )
        self.assertEqual(result.exit_code, 2)
        self.assertFalse(result.to_dict()["summary"]["coverage_complete"])
        self.assertEqual(scan_batch((clean, blocked)).exit_code, 1)
        self.assertEqual(scan_batch((clean, incomplete)).status, "incomplete")
        self.assertTrue(result.entries[1].rules)
        self.assertNotIn("PRIVATE_MARKER", result.render("json"))

    def test_shared_budget_is_streamed_and_unattempted_targets_are_explicit(self) -> None:
        first = self.source("first.txt", "12345")
        second = self.source("second.txt", "67890")
        third = self.source("third.txt", "abcde")
        result = scan_batch((first, second, third), batch_limits=BatchLimits(max_total_bytes=7))
        self.assertEqual(result.to_dict()["summary"]["charged_bytes"], 7)
        self.assertEqual(
            [entry.status for entry in result.entries], ["pass", "incomplete", "not-scanned"]
        )
        self.assertEqual(result.entries[1].effective_limits.max_total_bytes, 2)
        self.assertIsNone(result.entries[2].summary)
        self.assertEqual(result.entries[2].reason, "batch-byte-limit")
        self.assertEqual(result.exit_code, 1)

    def test_nested_archive_uses_the_same_batch_expanded_byte_budget(self) -> None:
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("ordinary.txt", "ordinary synthetic text\n" * 20)
        target = self.root / "nested.zip"
        target.write_bytes(stream.getvalue())
        other = self.source()
        total = target.stat().st_size + 5
        result = scan_batch((target, other), batch_limits=BatchLimits(max_total_bytes=total))
        self.assertLessEqual(result.to_dict()["summary"]["charged_bytes"], total)
        self.assertEqual(result.status, "incomplete")
        self.assertFalse(result.to_dict()["summary"]["coverage_complete"])

    def test_missing_target_does_not_spend_another_targets_budget(self) -> None:
        target = self.source(content="text")
        result = scan_batch(
            (self.root / "absent", target), batch_limits=BatchLimits(max_total_bytes=4)
        )
        self.assertEqual([entry.status for entry in result.entries], ["error", "pass"])
        self.assertEqual(result.entries[0].charged_bytes, 0)
        self.assertEqual(result.exit_code, 2)

    def test_output_has_no_names_evidence_or_active_html(self) -> None:
        target = self.source("person@example.test.txt", FICTIONAL_SECRET)
        result = scan_batch((target,), fail_on=Severity.CRITICAL)
        self.assertTrue(result.entries[0].rules)
        for format_name in ("json", "html", "console"):
            output = result.render(format_name)
            for marker in (
                target.name,
                str(self.root),
                FICTIONAL_SECRET,
                "evidence_fingerprint",
                "masked_preview",
            ):
                self.assertFalse(marker in output, "batch output repeated private context")
        markup = result.render("html")
        self.assertIn("Content-Security-Policy", markup)
        self.assertNotIn("<script", markup)
        self.assertNotIn("https://", markup)
        with self.assertRaises(DocumentInputError):
            result.render("unsupported")

    def test_target_count_is_validated_before_any_scan(self) -> None:
        target = self.source()
        with mock.patch("sharelint.batch._scan_with_context") as scanner:
            with self.assertRaises(DocumentInputError):
                scan_batch(
                    (self.root / f"item-{index}.txt" for index in range(5000)),
                    batch_limits=BatchLimits(max_targets=2),
                )
            scanner.assert_not_called()
        for targets in (
            (),
            (target, target.parent / "." / target.name),
            ("",),
            ("\0",),
            (7,),
            "string",
        ):
            with self.subTest(kind=type(targets).__name__), self.assertRaises(DocumentInputError):
                resolve_targets(targets)

    def test_invalid_batch_limits_reject_bool_and_unbounded_counts(self) -> None:
        with self.assertRaises(DocumentInputError):
            BatchResult((), BatchLimits(), ScanLimits(), Severity.HIGH)
        for value in (True, 0, -1, 1001, "1", 1.5):
            with self.subTest(value=value), self.assertRaises(DocumentInputError):
                BatchLimits(max_targets=value)
        for value in (True, 0, -1, 2**63, "1", 1.5):
            with self.subTest(value=value), self.assertRaises(DocumentInputError):
                BatchLimits(max_total_bytes=value)

    def test_manifest_paths_are_relative_to_its_own_directory(self) -> None:
        target = self.source("文件 空格.txt")
        manifest = self.root / "batch.toml"
        manifest.write_text('schema_version = 1\ntargets = ["文件 空格.txt"]\n', encoding="utf-8")
        self.assertEqual(read_batch_manifest(manifest), (target,))
        result = self.run_cli("batch", "--manifest", manifest, "--format", "json")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.json()["summary"]["target_count"], 1)
        self.assertNotIn(target.name, result.stdout)

    def test_manifest_validation_is_bounded_and_private(self) -> None:
        manifest = self.root / "batch.toml"
        cases = (
            b"PRIVATE_MARKER invalid TOML",
            b"schema_version = true\ntargets = []",
            b"schema_version = 2\ntargets = []",
            b"schema_version = 1\ntargets = [1]",
            b"schema_version = 1\ntargets = []\nupload = true",
            b"schema_version = 1\ntargets = ['a', 'b']",
            b"\xff",
            b" " * (64 * 1024 + 1),
        )
        for index, data in enumerate(cases):
            manifest.write_bytes(data)
            with self.subTest(index=index), self.assertRaises(DocumentInputError) as raised:
                read_batch_manifest(manifest, maximum=1)
            self.assertNotIn("PRIVATE_MARKER", str(raised.exception))
        manifest.write_text("schema_version = 1\ntargets = ['ordinary.txt']", encoding="utf-8")
        link = self.root / "manifest-link.toml"
        try:
            link.symlink_to(manifest)
        except OSError:
            return
        with self.assertRaises(DocumentInputError):
            read_batch_manifest(link)

    def test_cli_requires_explicit_new_outputs_outside_every_target(self) -> None:
        target = self.source()
        output = self.root / "report.json"
        result = self.run_cli("batch", target, "--format", "json", "-o", output)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(output.read_bytes())["status"], "pass")
        self.assertEqual(self.run_cli("batch", target, "-o", output).returncode, 2)
        directory = self.root / "source"
        directory.mkdir()
        self.assertEqual(
            self.run_cli("batch", directory, "-o", directory / "report.json").returncode, 2
        )
        self.assertEqual(self.run_cli("batch", target, "--format", "html").returncode, 2)
        self.assertEqual(self.run_cli("batch").returncode, 2)
        self.assertEqual(self.run_cli("batch", target, "--manifest", target).returncode, 2)
        html_output = self.root / "report.html"
        self.assertEqual(
            self.run_cli("batch", target, "--format", "html", "-o", html_output).returncode, 0
        )

    def test_config_limits_and_threshold_apply_but_coverage_cannot_be_disabled(self) -> None:
        target = self.source(content="contact: person@example.test\n")
        self.assertEqual(self.run_cli("batch", target).returncode, 0)
        self.assertEqual(self.run_cli("batch", target, "--profile", "public").returncode, 1)
        config = self.root / "policy.toml"
        config.write_text(
            "schema_version = 1\n[scan]\nstrict = false\n[limits]\nmax_file_bytes = 2\n",
            encoding="utf-8",
        )
        result = self.run_cli("batch", target, "--config", config, "--format", "json")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.json()["status"], "incomplete")
        self.assertTrue(result.json()["require_complete_coverage"])

    def test_cancellation_is_not_converted_into_a_partial_success(self) -> None:
        target = self.source()
        with (
            mock.patch("sharelint.batch._scan_with_context", side_effect=KeyboardInterrupt),
            self.assertRaises(KeyboardInterrupt),
        ):
            scan_batch((target,))

    def test_native_errors_are_private_and_scanning_continues(self) -> None:
        first, second = self.source(), self.source("other.txt")

        def scan_or_fail(path: Path, context: ScanContext) -> ScanReport:
            if path == first:
                raise OSError("PRIVATE_MARKER")
            return _scan_with_context(path, context)

        with mock.patch(
            "sharelint.batch._scan_with_context",
            side_effect=scan_or_fail,
        ):
            result = scan_batch((first, second))
        self.assertEqual([entry.status for entry in result.entries], ["error", "pass"])
        self.assertNotIn("PRIVATE_MARKER", result.render("json"))

    def test_per_target_limits_are_retained_with_a_smaller_remaining_budget(self) -> None:
        target = self.source(content="abc")
        result = scan_batch(
            (target,),
            limits=ScanLimits(max_total_bytes=20, max_findings=10),
            batch_limits=BatchLimits(max_total_bytes=5),
        )
        self.assertEqual(result.scan_limits.max_total_bytes, 20)
        self.assertEqual(result.entries[0].effective_limits.max_total_bytes, 5)
        self.assertEqual(result.entries[0].effective_limits.max_findings, 10)
