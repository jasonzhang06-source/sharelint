from __future__ import annotations

import json
import os
import stat
import subprocess
import unittest

import tests.bootstrap  # noqa: F401
from sharelint.filesystem import metadata_is_reparse_point
from tests.cli_harness import CliTestCase
from tests.contract import SEVERITIES, assert_scan_contract
from tests.helpers import FICTIONAL_NAME, FICTIONAL_SECRET, write_jpeg, write_pdf


class CliContractTests(CliTestCase):
    def test_root_help_advertises_the_three_public_commands(self) -> None:
        result = self.run_cli("--help")

        self.assertEqual(result.returncode, 0)
        help_text = (result.stdout + result.stderr).lower()
        for command in ("scan", "pack", "demo"):
            with self.subTest(command=command):
                self.assertIn(command, help_text)
        self.assertIn("examples:", help_text)
        self.assertIn("sharelint scan ./client-handoff", help_text)
        self.assertIn("sharelint pack ./approved-files -o share-ready.zip", help_text)
        self.assertNotIn("traceback", help_text)

    def test_command_help_explains_outputs_and_copyable_examples(self) -> None:
        scan_help = self.run_cli("scan", "--help")
        pack_help = self.run_cli("pack", "--help")
        demo_help = self.run_cli("demo", "--help")

        for result in (scan_help, pack_help, demo_help):
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("examples:", result.stdout.lower())
            self.assertNotIn("traceback", (result.stdout + result.stderr).lower())
        self.assertIn("nothing is uploaded or modified", scan_help.stdout.lower())
        self.assertIn("new shareable zip path", pack_help.stdout.lower())
        self.assertIn("synthetic input zip", demo_help.stdout.lower())
        self.assertIn("html requires --report", demo_help.stdout.lower())
        self.assertIn("coverage gaps block packing", pack_help.stdout.lower())

    def test_unknown_rule_does_not_echo_untrusted_terminal_input(self) -> None:
        result = self.run_cli("explain", "FICTITIOUS_RULE\x1b[2J\u202e")
        self.assertEqual(result.returncode, 2)
        self.assertIn("sharelint rules", result.stderr)
        self.assertNotIn("FICTITIOUS_RULE", result.stderr)
        self.assertNotIn("\x1b", result.stderr)
        self.assertNotIn("\u202e", result.stderr)

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

    def test_human_reports_say_review_when_findings_are_below_threshold(self) -> None:
        review = self.root / "review.txt"
        review.write_text("Contact reviewer@example.test\n", encoding="utf-8")

        console = self.run_cli("scan", review)
        html = self.run_cli("scan", review, "--format", "html")
        machine = self.run_cli("scan", review, "--format", "json")

        self.assertEqual(console.returncode, 0, console.stderr)
        self.assertIn("REVIEW · 0 policy-blocking", console.stdout)
        self.assertNotIn("\nPASS ·", console.stdout)
        self.assertIn("below the selected blocking threshold", console.stdout)
        self.assertEqual(html.returncode, 0, html.stderr)
        self.assertIn(">REVIEW</span>", html.stdout)
        self.assertNotIn(">PASS</span>", html.stdout)
        self.assertEqual(machine.returncode, 0, machine.stderr)
        self.assertEqual(machine.json()["summary"]["verdict"], "pass")

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
        self.assertIn("synthetic demo", output)
        self.assertIn("no personal files were read", output)
        self.assertIn("next steps", output)
        self.assertIn("sharelint scan ./path-to-share", output)
        self.assertIn("sharelint pack ./approved-files -o share-ready.zip", output)
        self.assertNotIn("traceback", output)

    def test_demo_html_requires_an_explicit_report_path_before_creating_files(self) -> None:
        bundle = self.root / "synthetic-input.zip"

        result = self.run_cli("demo", "-o", bundle, "--format", "html")

        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("requires --report <path>", result.stderr)
        self.assertIn(
            "sharelint demo --format html --report sharelint-demo.html",
            result.stderr,
        )
        self.assertNotIn("<!doctype html>", result.stdout + result.stderr)
        self.assertFalse(bundle.exists())

    def test_demo_output_never_follows_a_symlink(self) -> None:
        escaped = self.root / "escaped.zip"
        dangling = self.root / "dangling.zip"
        try:
            dangling.symlink_to(escaped)
        except OSError:
            if os.name == "nt":
                self.skipTest("this Windows environment does not permit symbolic-link creation")
            raise

        through_symlink = self.run_cli("demo", "-o", dangling)

        self.assertEqual(through_symlink.returncode, 2)
        self.assertTrue(dangling.is_symlink())
        self.assertFalse(escaped.exists())

    def test_demo_output_never_overwrites_a_path(self) -> None:
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

    def test_redirected_output_is_utf8_even_under_a_legacy_code_page(self) -> None:
        target = self.root / "unicode-output"
        target.mkdir()
        (target / "finding.txt").write_text(FICTIONAL_SECRET, encoding="utf-8")

        result = self.run_cli(
            "scan",
            target,
            "--format",
            "html",
            env_overrides={"PYTHONIOENCODING": "cp1252:strict", "PYTHONUTF8": "0"},
        )

        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("→", result.stdout)
        self.assertNotIn("unicodeencodeerror", result.stderr.lower())

    @unittest.skipUnless(os.name == "nt", "Windows junction contract requires Windows")
    def test_windows_junction_is_reported_without_leaving_the_boundary(self) -> None:
        boundary = self.root / "boundary"
        outside = self.root / "outside"
        junction = boundary / "linked-directory"
        boundary.mkdir()
        outside.mkdir()
        outside_marker = "FICTITIOUS_JUNCTION_ESCAPE_MARKER"
        (outside / "outside.txt").write_text(outside_marker, encoding="utf-8")

        created = subprocess.run(
            ("cmd.exe", "/d", "/c", "mklink", "/J", str(junction), str(outside)),
            check=False,
            capture_output=True,
            timeout=10,
        )
        if created.returncode != 0:
            if os.environ.get("GITHUB_ACTIONS") == "true":
                self.fail("GitHub Windows runner could not create the junction fixture")
            self.skipTest("this Windows environment does not permit junction creation")
        self.assertTrue(
            metadata_is_reparse_point(junction.stat(follow_symlinks=False)),
            "the native Windows fixture was not reported as a reparse point",
        )

        result = self.run_cli("scan", boundary, "--format", "json")

        self.assertEqual(result.returncode, 1, result.stderr)
        payload = result.json()
        findings = assert_scan_contract(payload)
        self.assertTrue(any(item["rule_id"] == "SL.ARCHIVE.SYMLINK" for item in findings))
        self.assertFalse(payload["summary"]["coverage_complete"])
        self.assertNotIn(outside_marker, result.stdout + result.stderr)

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

    def test_pack_labels_shareable_and_private_outputs(self) -> None:
        source = self.root / "approved.txt"
        source.write_text("ordinary public-domain synthetic text\n", encoding="utf-8")
        bundle = self.root / "share-ready.zip"

        result = self.run_cli("pack", source, "-o", bundle)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"Shareable bundle · {bundle}", result.stdout)
        self.assertIn("Keep private · scan report ·", result.stdout)
        self.assertIn("Keep private · verification receipt ·", result.stdout)
        self.assertNotIn("\nWrote ", result.stdout)


if __name__ == "__main__":
    unittest.main()
