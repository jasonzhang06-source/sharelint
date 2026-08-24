from __future__ import annotations

import json
import os
import stat
import unittest

from tests.cli_harness import CliTestCase
from tests.contract import SEVERITIES, assert_scan_contract
from tests.helpers import FICTIONAL_NAME, write_jpeg, write_pdf


class CliContractTests(CliTestCase):
    def test_root_help_advertises_the_three_public_commands(self) -> None:
        result = self.run_cli("--help")

        self.assertEqual(result.returncode, 0)
        help_text = (result.stdout + result.stderr).lower()
        for command in ("scan", "pack", "demo"):
            with self.subTest(command=command):
                self.assertIn(command, help_text)
        self.assertNotIn("traceback", help_text)

    def test_usage_errors_have_exit_code_two_and_no_traceback(self) -> None:
        cases = [
            (),
            ("scan",),
            ("pack",),
            ("scan", "somewhere", "--format", "xml"),
            ("scan", "somewhere", "--fail-on", "severe"),
            ("unknown-command",),
        ]
        for args in cases:
            with self.subTest(args=args):
                result = self.run_cli(*args)
                self.assertEqual(result.returncode, 2)
                self.assertNotIn("traceback", (result.stdout + result.stderr).lower())

    def test_missing_input_has_exit_code_two(self) -> None:
        missing = self.root / "FICTITIOUS_DOES_NOT_EXIST"

        result = self.run_cli("scan", missing, "--format", "json")

        self.assertEqual(result.returncode, 2)
        self.assertNotIn("traceback", (result.stdout + result.stderr).lower())

    def test_clean_scan_returns_zero_and_machine_readable_summary(self) -> None:
        clean = self.root / "ordinary.txt"
        clean.write_text("ordinary public-domain synthetic text\n", encoding="utf-8")

        result = self.run_cli("scan", clean, "--format", "json")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(assert_scan_contract(result.json()), [])

    def test_scan_output_is_atomic_non_overwriting_and_outside_the_target(self) -> None:
        source = self.root / "ordinary.txt"
        original = b"ordinary public-domain synthetic text\n"
        source.write_bytes(original)

        same_file = self.run_cli("scan", source, "-o", source)
        self.assertEqual(same_file.returncode, 2)
        self.assertEqual(source.read_bytes(), original)

        existing = self.root / "existing.json"
        sentinel = b"FICTITIOUS_EXISTING_REPORT\n"
        existing.write_bytes(sentinel)
        overwrite = self.run_cli("scan", source, "--format", "json", "-o", existing)
        self.assertEqual(overwrite.returncode, 2)
        self.assertEqual(existing.read_bytes(), sentinel)

        directory = self.root / "boundary"
        directory.mkdir()
        (directory / "input.txt").write_bytes(original)
        inside = directory / "report.json"
        nested_output = self.run_cli("scan", directory, "--format", "json", "-o", inside)
        self.assertEqual(nested_output.returncode, 2)
        self.assertFalse(inside.exists())
        self.assertEqual((directory / "input.txt").read_bytes(), original)

        report_path = self.root / "new-report.json"
        written = self.run_cli("scan", source, "--format", "json", "-o", report_path)
        self.assertEqual(written.returncode, 0, written.stderr)
        self.assertEqual(written.stdout, "")
        assert_scan_contract(json.loads(report_path.read_text(encoding="utf-8")))
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(report_path.stat().st_mode), 0o600)

    def test_fail_on_uses_severity_threshold_and_still_emits_report(self) -> None:
        metadata_only = write_pdf(
            self.root / "metadata.pdf",
            text="ordinary synthetic PDF text",
            author=FICTIONAL_NAME,
        )
        baseline = self.run_cli("scan", metadata_only, "--format", "json")
        self.assertEqual(baseline.returncode, 0, baseline.stderr)
        scan_findings = assert_scan_contract(baseline.json())
        self.assertEqual(
            [(item["rule_id"], item["severity"]) for item in scan_findings],
            [("SL.PDF.AUTHOR_METADATA", "medium")],
        )
        highest = max(SEVERITIES.index(item["severity"]) for item in scan_findings)

        for threshold, level in enumerate(SEVERITIES):
            with self.subTest(level=level):
                result = self.run_cli(
                    "scan",
                    metadata_only,
                    "--format",
                    "json",
                    "--fail-on",
                    level,
                )
                self.assertEqual(result.returncode, 1 if highest >= threshold else 0)
                assert_scan_contract(result.json())

    def test_partial_coverage_has_an_incomplete_not_pass_verdict(self) -> None:
        partial_image = write_jpeg(
            self.root / "partial.jpg",
            description="",
            artist="",
        )

        result = self.run_cli("scan", partial_image, "--format", "json")

        self.assertEqual(result.returncode, 0, result.stderr)
        payload = result.json()
        self.assertEqual(assert_scan_contract(payload), [])
        self.assertFalse(payload["summary"]["coverage_complete"])
        self.assertEqual(payload["summary"]["blocking_findings"], 0)
        self.assertEqual(payload["summary"]["verdict"], "incomplete")
        self.assertTrue(any(surface.get("status") == "partial" for surface in payload["surfaces"]))

    def test_demo_is_self_contained_and_successful(self) -> None:
        result = self.run_cli("demo")

        self.assertEqual(result.returncode, 0, result.stderr)
        output = (result.stdout + result.stderr).lower()
        self.assertIn("sharelint", output)
        self.assertIn("client-handoff.zip", output)
        self.assertIn("sl.", output)
        self.assertNotIn("traceback", output)

    def test_demo_output_never_follows_or_overwrites_a_path(self) -> None:
        escaped = self.root / "escaped.zip"
        dangling = self.root / "dangling.zip"
        dangling.symlink_to(escaped)

        through_symlink = self.run_cli("demo", "-o", dangling)

        self.assertEqual(through_symlink.returncode, 2)
        self.assertTrue(dangling.is_symlink())
        self.assertFalse(escaped.exists())

        existing = self.root / "existing.zip"
        sentinel = b"FICTITIOUS_EXISTING_DEMO\n"
        existing.write_bytes(sentinel)
        overwrite = self.run_cli("demo", "-o", existing)
        self.assertEqual(overwrite.returncode, 2)
        self.assertEqual(existing.read_bytes(), sentinel)

        created = self.root / "new-demo.zip"
        success = self.run_cli("demo", "-o", created)
        self.assertEqual(success.returncode, 0, success.stderr)
        self.assertTrue(created.read_bytes().startswith(b"PK"))
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(created.stat().st_mode), 0o600)

    def test_demo_writes_a_report_without_printing_or_overwriting(self) -> None:
        report = self.root / "synthetic-demo.html"

        success = self.run_cli(
            "demo",
            "--format",
            "html",
            "--report",
            report,
        )

        self.assertEqual(success.returncode, 0, success.stderr)
        self.assertEqual(success.stdout, "")
        rendered = report.read_text(encoding="utf-8")
        self.assertTrue(rendered.startswith("<!doctype html>"))
        self.assertIn("Coverage ledger", rendered)
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(report.stat().st_mode), 0o600)

        sentinel = "FICTITIOUS_EXISTING_REPORT\n"
        report.write_text(sentinel, encoding="utf-8")
        refused = self.run_cli("demo", "--format", "html", "--report", report)
        self.assertEqual(refused.returncode, 2)
        self.assertEqual(report.read_text(encoding="utf-8"), sentinel)

        bundle = self.root / "reusable-demo.zip"
        bundle_report = self.root / "reusable-demo.json"
        combined = self.run_cli(
            "demo",
            "-o",
            bundle,
            "--format",
            "json",
            "--report",
            bundle_report,
        )
        self.assertEqual(combined.returncode, 0, combined.stderr)
        self.assertEqual(combined.stdout, "")
        self.assertTrue(bundle.read_bytes().startswith(b"PK"))
        self.assertEqual(bundle_report.read_text(encoding="utf-8")[0], "{")

        shared_path = self.root / "same-output"
        same_output = self.run_cli("demo", "-o", shared_path, "--report", shared_path)
        self.assertEqual(same_output.returncode, 2)
        self.assertFalse(shared_path.exists())


if __name__ == "__main__":
    unittest.main()
