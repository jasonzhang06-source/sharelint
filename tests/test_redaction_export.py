from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from unittest import mock

import tests.bootstrap  # noqa: F401
from sharelint.input_io import DocumentInputError
from sharelint.models import ScanLimits
from sharelint.redaction import RedactionBlocked, create_redaction_plan
from sharelint.redaction_export import apply_redaction_plan, verify_redaction
from sharelint.scanner import scan
from sharelint.verification import VerificationError
from tests.cli_harness import CliTestCase
from tests.helpers import FICTIONAL_SECRET


class RedactionExportTests(CliTestCase):
    def setup_plan(self) -> tuple[Path, Path, Path]:
        source = self.root / "private.txt"
        source.write_bytes(
            ("你好\r\n" + FICTIONAL_SECRET + "\r\ncontact: person@example.test\r\n").encode()
        )
        plan = self.root / "redaction.plan.json"
        plan.write_bytes(create_redaction_plan(source, output_name="public.txt").payload)
        return source, plan, self.root / "public.txt"

    def test_roundtrip_preserves_original_and_verifies_exact_derivative(self) -> None:
        source, plan, output = self.setup_plan()
        original = source.read_bytes()
        artifact = apply_redaction_plan(source, plan, output)
        self.assertEqual(source.read_bytes(), original)
        self.assertNotEqual(output.read_bytes(), original)
        self.assertEqual(scan(output).findings, [])
        self.assertIn("你好\r\n", output.read_bytes().decode())
        self.assertEqual(len(list(self.root.glob(".sharelint-redact-*"))), 0)
        verified = verify_redaction(
            output,
            artifact.receipt,
            artifact.report_output,
            plan,
            expected_receipt_sha256=hashlib.sha256(artifact.receipt.read_bytes()).hexdigest(),
        )
        self.assertEqual(verified.output_sha256, artifact.output_sha256)
        self.assertEqual(verified.to_dict()["status"], "verified")
        self.assertIn("not authentication", verified.to_dict()["claim"])
        for path in (plan, artifact.receipt, artifact.report_output):
            text = path.read_text(encoding="utf-8")
            for marker in (FICTIONAL_SECRET, "person@example.test", str(self.root)):
                self.assertFalse(
                    marker in text, "redaction metadata repeated private source context"
                )

    def test_changed_source_basename_destination_policy_or_producer_is_rejected(self) -> None:
        source, plan, output = self.setup_plan()
        renamed = self.root / "renamed.txt"
        renamed.write_bytes(source.read_bytes())
        cases = (
            (renamed, plan, output, {}),
            (source, plan, self.root / "other-name.txt", {}),
            (source, plan, output, {"limits": ScanLimits(max_findings=9000)}),
        )
        for target, selected_plan, destination, kwargs in cases:
            with self.subTest(name=destination.name), self.assertRaises(DocumentInputError):
                apply_redaction_plan(target, selected_plan, destination, **kwargs)
            self.assertFalse(destination.exists())
        with (
            mock.patch("sharelint.redaction_export.__version__", "999.0.0"),
            self.assertRaises(DocumentInputError),
        ):
            apply_redaction_plan(source, plan, output)
        source.write_bytes(b"changed synthetic content")
        with self.assertRaises(DocumentInputError):
            apply_redaction_plan(source, plan, output)
        self.assertFalse(output.exists())

    def test_source_changes_at_the_final_recheck_roll_back_before_publication(self) -> None:
        source, plan, output = self.setup_plan()
        from sharelint.redaction_export import _source_still_matches

        def change_then_check(target: Path, selected_plan: object) -> None:
            target.write_bytes(b"operator changed source")
            _source_still_matches(target, selected_plan)

        with (
            mock.patch(
                "sharelint.redaction_export._source_still_matches", side_effect=change_then_check
            ),
            self.assertRaises(DocumentInputError),
        ):
            apply_redaction_plan(source, plan, output)
        self.assertEqual(source.read_bytes(), b"operator changed source")
        self.assertFalse(output.exists())
        self.assertEqual(list(self.root.glob(".sharelint-redact-*")), [])

    def test_cancellation_and_receipt_write_failures_remove_only_our_publications(self) -> None:
        source, plan, output = self.setup_plan()
        original = source.read_bytes()
        for failure in (KeyboardInterrupt(), OSError("PRIVATE_MARKER")):
            with (
                mock.patch("sharelint.redaction_export._write_document", side_effect=failure),
                self.assertRaises(
                    KeyboardInterrupt
                    if isinstance(failure, KeyboardInterrupt)
                    else DocumentInputError
                ),
            ):
                apply_redaction_plan(source, plan, output)
            self.assertFalse(output.exists())
            self.assertFalse(Path(f"{output}.sharelint-redact.report.json").exists())
            self.assertFalse(Path(f"{output}.sharelint-redact.json").exists())
            self.assertEqual(source.read_bytes(), original)
            self.assertEqual(list(self.root.glob(".*.tmp")), [])

    def test_fresh_output_rescan_and_publication_identity_are_required(self) -> None:
        source, plan, output = self.setup_plan()
        private_report = scan(source)
        with (
            mock.patch("sharelint.redaction_export.scan", return_value=private_report),
            self.assertRaises(DocumentInputError),
        ):
            apply_redaction_plan(source, plan, output)
        self.assertFalse(output.exists())
        private_report.target_sha256 = json.loads(plan.read_bytes())["output"]["sha256"]
        with (
            mock.patch("sharelint.redaction_export.scan", return_value=private_report),
            self.assertRaises(RedactionBlocked),
        ):
            apply_redaction_plan(source, plan, output)
        with (
            mock.patch("sharelint.packing._publication_matches", return_value=False),
            self.assertRaises(DocumentInputError),
        ):
            apply_redaction_plan(source, plan, output)
        self.assertFalse(output.exists())
        self.assertEqual(list(self.root.glob("*.sharelint-redact*")), [])

    def test_existing_outputs_and_aliases_never_overwrite_originals(self) -> None:
        source, plan, output = self.setup_plan()
        original = source.read_bytes()
        for destination, receipt, report in (
            (source, None, None),
            (plan, None, None),
            (output, source, None),
            (output, plan, None),
            (output, output, None),
            (output, None, output),
            (self.root / "absent" / "public.txt", None, None),
        ):
            with self.subTest(destination=destination.name), self.assertRaises(DocumentInputError):
                apply_redaction_plan(
                    source, plan, destination, receipt=receipt, report_output=report
                )
        output.write_bytes(b"existing operator content")
        with self.assertRaises(DocumentInputError):
            apply_redaction_plan(source, plan, output)
        self.assertEqual(output.read_bytes(), b"existing operator content")
        self.assertEqual(source.read_bytes(), original)

    def test_a_blocked_plan_is_not_an_authorization(self) -> None:
        source, plan, output = self.setup_plan()
        plan.write_bytes(
            create_redaction_plan(source, output_name="public.txt", rules=["SL.PII.EMAIL"]).payload
        )
        with self.assertRaises(RedactionBlocked):
            apply_redaction_plan(source, plan, output)
        self.assertFalse(output.exists())

    def test_verification_rejects_mutated_plan_report_output_and_receipt(self) -> None:
        source, plan, output = self.setup_plan()
        artifact = apply_redaction_plan(source, plan, output)
        for path in (plan, artifact.report_output, output):
            original = path.read_bytes()
            path.write_bytes(original + b"\n")
            with self.subTest(kind=path.suffix), self.assertRaises(VerificationError):
                verify_redaction(output, artifact.receipt, artifact.report_output, plan)
            path.write_bytes(original)
        original_receipt = artifact.receipt.read_bytes()
        document = json.loads(original_receipt)
        document["edit_count"] += 1
        artifact.receipt.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(VerificationError):
            verify_redaction(output, artifact.receipt, artifact.report_output, plan)
        artifact.receipt.write_bytes(original_receipt)
        with self.assertRaises(VerificationError):
            verify_redaction(
                output,
                artifact.receipt,
                artifact.report_output,
                plan,
                expected_receipt_sha256="0" * 64,
            )

    def test_receipt_types_are_validated_without_bool_integer_coercion(self) -> None:
        source, plan, output = self.setup_plan()
        artifact = apply_redaction_plan(source, plan, output)
        original = json.loads(artifact.receipt.read_bytes())
        cases = []
        for keys in (
            ("output", "size"),
            ("summary", "error_count"),
            ("summary", "total_findings"),
            ("policy", "limits", "max_total_bytes"),
            ("verification", "source_rechecked"),
        ):
            document = copy.deepcopy(original)
            parent = document
            for key in keys[:-1]:
                parent = parent[key]
            parent[keys[-1]] = 1 if keys[0] == "verification" else False
            cases.append(document)
        document = copy.deepcopy(original)
        document["raw_evidence"] = "PRIVATE_MARKER"
        cases.append(document)
        for index, document in enumerate(cases):
            artifact.receipt.write_text(json.dumps(document), encoding="utf-8")
            with self.subTest(index=index), self.assertRaises(DocumentInputError):
                verify_redaction(output, artifact.receipt, artifact.report_output, plan)

    def test_verifier_uses_operator_budgets_not_the_plan(self) -> None:
        source, plan, output = self.setup_plan()
        artifact = apply_redaction_plan(source, plan, output)
        with self.assertRaises(DocumentInputError):
            verify_redaction(
                output,
                artifact.receipt,
                artifact.report_output,
                plan,
                limits=ScanLimits(max_file_bytes=2),
            )

    def test_imported_claims_and_output_path_representations_stay_private(self) -> None:
        source, plan, output = self.setup_plan()
        artifact = apply_redaction_plan(
            source, plan, output, receipt=self.root / "PRIVATE_MARKER-receipt.json"
        )
        self.assertNotIn("PRIVATE_MARKER", repr(artifact))
        document = json.loads(artifact.receipt.read_bytes())
        document["claim"] = "PRIVATE_MARKER\u001b[31m"
        artifact.receipt.write_text(json.dumps(document), encoding="utf-8")
        verified = verify_redaction(output, artifact.receipt, artifact.report_output, plan)
        self.assertNotIn("PRIVATE_MARKER", json.dumps(verified.to_dict()))

    def test_cli_roundtrip_inspection_and_repeat_rejection(self) -> None:
        source, _, output = self.setup_plan()
        plan = self.root / "cli-plan.json"
        created = self.run_cli("redact", "plan", source, "--name", output.name, "-o", plan)
        self.assertEqual(created.returncode, 0, created.stderr)
        self.assertFalse(output.exists())
        inspected = self.run_cli("redact", "inspect", plan, "--format", "json")
        self.assertEqual(inspected.returncode, 0, inspected.stderr)
        self.assertGreater(inspected.json()["edit_count"], 0)
        self.assertNotIn("person@example.test", inspected.stdout)
        self.assertEqual(self.run_cli("redact", "inspect", plan).returncode, 0)
        applied = self.run_cli("redact", "apply", source, "--plan", plan, "-o", output)
        self.assertEqual(applied.returncode, 0, applied.stderr)
        receipt, report = (
            Path(f"{output}.sharelint-redact.json"),
            Path(f"{output}.sharelint-redact.report.json"),
        )
        verified = self.run_cli(
            "redact",
            "verify",
            output,
            "--plan",
            plan,
            "--receipt",
            receipt,
            "--report",
            report,
            "--format",
            "json",
        )
        self.assertEqual(verified.returncode, 0, verified.stderr)
        self.assertEqual(verified.json()["status"], "verified")
        self.assertEqual(
            self.run_cli("redact", "apply", source, "--plan", plan, "-o", output).returncode, 2
        )
        self.assertEqual(self.run_cli("redact", "plan", source, "-o", plan).returncode, 2)
        output.write_bytes(b"mutated output")
        self.assertEqual(
            self.run_cli(
                "redact", "verify", output, "--plan", plan, "--receipt", receipt, "--report", report
            ).returncode,
            1,
        )

    def test_cli_reports_blocked_plans_and_private_operational_errors(self) -> None:
        source, _, output = self.setup_plan()
        plan = self.root / "blocked-plan.json"
        result = self.run_cli(
            "redact", "plan", source, "--rule", "SL.PII.EMAIL", "--name", output.name, "-o", plan
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(self.run_cli("redact", "inspect", plan).returncode, 1)
        self.assertEqual(
            self.run_cli("redact", "apply", source, "--plan", plan, "-o", output).returncode, 1
        )
        invalid = self.root / "invalid.json"
        invalid.write_bytes(b"PRIVATE_MARKER not JSON")
        result = self.run_cli("redact", "inspect", invalid)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("PRIVATE_MARKER", result.stderr)

    def test_looping_symlink_does_not_leak_a_traceback(self) -> None:
        loop = self.root / "PRIVATE_MARKER-loop"
        try:
            loop.symlink_to(loop)
        except OSError:
            return
        for index, command in enumerate((("scan", loop), ("redact", "plan", loop))):
            result = self.run_cli(*command, "-o", self.root / f"not-created-{index}.json")
            self.assertIn(result.returncode, (1, 2) if index == 0 else (2,))
            self.assertNotIn("PRIVATE_MARKER", result.stderr)
            self.assertNotIn("Traceback", result.stderr)
