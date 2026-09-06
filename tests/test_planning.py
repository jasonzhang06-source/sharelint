from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import replace
from pathlib import Path
from unittest import mock

import tests.bootstrap  # noqa: F401
from sharelint.input_io import DocumentInputError
from sharelint.models import ScanLimits, Severity
from sharelint.packing import PackError, pack
from sharelint.planning import create_plan, read_plan, validate_plan
from sharelint.reporters import canonical_json
from sharelint.scanner import scan
from sharelint.verification import VerificationError, verify_receipt
from tests.cli_harness import CliTestCase
from tests.helpers import FICTIONAL_SECRET


class PlanningTests(CliTestCase):
    def source(self) -> Path:
        path = self.root / "ordinary.txt"
        path.write_text("ordinary synthetic public text\n", encoding="utf-8")
        return path

    def plan_for(self, source: Path) -> Path:
        path = self.root / "handoff-plan.json"
        path.write_bytes(create_plan(source).payload)
        return path

    def test_snapshot_is_stable_without_cross_run_evidence_fingerprints(self) -> None:
        source = self.source()
        source.write_text("contact: person@example.test\n", encoding="utf-8")
        first, second = create_plan(source), create_plan(source)
        self.assertTrue(first.ready)
        self.assertNotEqual(first.report.fingerprint_scope, second.report.fingerprint_scope)
        self.assertEqual(first.document["snapshot_sha256"], second.document["snapshot_sha256"])
        self.assertNotEqual(first.sha256, second.sha256)
        first.require_match(source, second.report, Severity.HIGH)
        self.assertNotIn("person@example.test", first.payload.decode())

    def test_plan_pack_and_verification_bind_the_exact_plan(self) -> None:
        source = self.source()
        plan = self.plan_for(source)
        bundle, receipt, report = (
            self.root / name for name in ("delivery.zip", "receipt.json", "report.json")
        )
        pack(source, bundle, receipt=receipt, report_output=report, plan=plan)
        document = json.loads(receipt.read_bytes())
        self.assertEqual(document["schema_version"], "2.0.0")
        self.assertEqual(document["plan"]["sha256"], hashlib.sha256(plan.read_bytes()).hexdigest())
        result = verify_receipt(receipt, report, bundle, plan_path=plan)
        self.assertEqual(result.status, "verified")
        self.assertIn("handoff-plan-binding", result.checks)
        with self.assertRaises(DocumentInputError):
            verify_receipt(receipt, report, bundle)
        plan.write_bytes(plan.read_bytes() + b"\n")
        with self.assertRaises(VerificationError):
            verify_receipt(receipt, report, bundle, plan_path=plan)

    def test_content_or_basename_changes_invalidate_the_plan(self) -> None:
        source = self.source()
        plan = self.plan_for(source)
        renamed = self.root / "renamed.txt"
        renamed.write_bytes(source.read_bytes())
        with self.assertRaises(DocumentInputError):
            pack(renamed, self.root / "renamed.zip", plan=plan)
        source.write_text("changed ordinary synthetic text\n", encoding="utf-8")
        with self.assertRaises(DocumentInputError):
            pack(source, self.root / "changed.zip", plan=plan)
        self.assertFalse((self.root / "renamed.zip").exists())
        self.assertFalse((self.root / "changed.zip").exists())

    def test_policy_version_and_scan_snapshot_changes_are_rejected(self) -> None:
        source = self.source()
        plan = create_plan(source)
        report = scan(source)
        with self.assertRaises(DocumentInputError):
            plan.require_match(source, report, Severity.LOW)
        report.tool_version = "999.0.0"
        with self.assertRaises(DocumentInputError):
            plan.require_match(source, report, Severity.HIGH)
        report = scan(source)
        report.surfaces[0] = replace(report.surfaces[0], note="different inspection")
        with self.assertRaises(DocumentInputError):
            plan.require_match(source, report, Severity.HIGH)
        report = scan(source, limits=ScanLimits(max_file_bytes=1024))
        with self.assertRaises(DocumentInputError):
            plan.require_match(source, report, Severity.HIGH)

    def test_blocked_plan_cannot_override_findings_or_coverage(self) -> None:
        source = self.source()
        source.write_text(FICTIONAL_SECRET, encoding="utf-8")
        plan_path = self.plan_for(source)
        self.assertFalse(read_plan(plan_path).ready)
        with self.assertRaises(DocumentInputError):
            pack(source, self.root / "blocked.zip", plan=plan_path)
        self.assertFalse((self.root / "blocked.zip").exists())
        source.write_bytes(b"%PDF-1.4\n%%EOF")
        self.assertFalse(create_plan(source).ready)

    def test_plan_requires_a_receipt_and_unplanned_packs_do_not_claim_a_plan(self) -> None:
        source = self.source()
        plan = self.plan_for(source)
        with self.assertRaises(PackError):
            pack(source, self.root / "without.zip", plan=plan, write_receipt=False)
        bundle, receipt, report = (
            self.root / name for name in ("legacy.zip", "legacy.json", "legacy.report.json")
        )
        pack(source, bundle, receipt=receipt, report_output=report)
        document = json.loads(receipt.read_bytes())
        self.assertEqual(document["schema_version"], "2.0.0")
        self.assertNotIn("plan", document)
        with self.assertRaises(DocumentInputError):
            verify_receipt(receipt, report, bundle, plan_path=plan)

    def test_control_document_tampering_and_unknown_fields_are_rejected(self) -> None:
        original = create_plan(self.source()).document
        for key, value in (
            ("status", "blocked"),
            ("schema_version", "9.0.0"),
            ("private", "PRIVATE_MARKER"),
            ("created_at", "2026-99-01T00:00:00Z"),
            ("snapshot_sha256", "0" * 64),
        ):
            changed = copy.deepcopy(original)
            changed[key] = value
            with self.subTest(key=key), self.assertRaises(DocumentInputError):
                validate_plan(json.dumps(changed).encode())
        changed = copy.deepcopy(original)
        changed["source"]["sha256"] = "0" * 64
        with self.assertRaises(DocumentInputError):
            validate_plan(json.dumps(changed).encode())

    def test_a_forged_ready_flag_with_recomputed_document_hash_still_fails(self) -> None:
        source = self.source()
        source.write_text(FICTIONAL_SECRET, encoding="utf-8")
        doc = create_plan(source).document
        doc["status"] = "ready"
        doc["document_sha256"] = hashlib.sha256(
            canonical_json(
                {key: value for key, value in doc.items() if key != "document_sha256"}
            ).encode()
        ).hexdigest()
        with self.assertRaises(DocumentInputError):
            validate_plan(json.dumps(doc).encode())

    def test_pack_checks_the_review_snapshot_again_before_publication(self) -> None:
        source = self.source()
        plan = self.plan_for(source)
        from sharelint import packing

        real_scan = packing.scan
        count = 0

        def changed_last_scan(*args: object, **kwargs: object):
            nonlocal count
            count += 1
            report = real_scan(*args, **kwargs)
            if count == 3:
                report.surfaces[0] = replace(report.surfaces[0], note="changed final inspection")
            return report

        with (
            mock.patch("sharelint.packing.scan", side_effect=changed_last_scan),
            self.assertRaises(DocumentInputError),
        ):
            pack(source, self.root / "not-published.zip", plan=plan)
        self.assertFalse((self.root / "not-published.zip").exists())

    def test_cli_create_inspect_pack_and_verify(self) -> None:
        source = self.source()
        plan = self.root / "plan.json"
        made = self.run_cli("plan", "create", source, "-o", plan)
        self.assertEqual(made.returncode, 0, made.stderr)
        inspected = self.run_cli("plan", "inspect", plan, "--format", "json")
        self.assertEqual(inspected.returncode, 0, inspected.stderr)
        self.assertEqual(inspected.json()["status"], "ready")
        self.assertNotIn("ordinary.txt", inspected.stdout)
        console = self.run_cli("plan", "inspect", plan)
        self.assertEqual(console.returncode, 0)
        self.assertIn("not approval", console.stdout)
        duplicate = self.run_cli("plan", "create", source, "-o", plan)
        self.assertEqual(duplicate.returncode, 2)
        bundle, receipt, report = (
            self.root / name for name in ("planned.zip", "receipt.json", "report.json")
        )
        packed = self.run_cli(
            "pack", source, "--plan", plan, "-o", bundle, "--receipt", receipt, "--report", report
        )
        self.assertEqual(packed.returncode, 0, packed.stderr)
        verified = self.run_cli(
            "verify",
            bundle,
            "--receipt",
            receipt,
            "--report",
            report,
            "--plan",
            plan,
            "--format",
            "json",
        )
        self.assertEqual(verified.returncode, 0, verified.stderr)
        self.assertIn("handoff-plan-binding", verified.json()["checks"])

    def test_cli_blocks_coverage_and_plan_output_inside_input(self) -> None:
        source = self.root / "handoff"
        source.mkdir()
        (source / "document.pdf").write_bytes(b"%PDF-1.4\n%%EOF")
        plan = self.root / "blocked.json"
        made = self.run_cli("plan", "create", source, "-o", plan)
        self.assertEqual(made.returncode, 1, made.stderr)
        self.assertEqual(self.run_cli("plan", "inspect", plan).returncode, 1)
        inside = self.run_cli("plan", "create", source, "-o", source / "plan.json")
        self.assertEqual(inside.returncode, 2)
        self.assertFalse((source / "plan.json").exists())

    def test_plan_configuration_must_be_repeated_for_pack(self) -> None:
        source = self.source()
        plan = self.root / "public-plan.json"
        made = self.run_cli("plan", "create", source, "--profile", "public", "-o", plan)
        self.assertEqual(made.returncode, 0, made.stderr)
        mismatch = self.run_cli("pack", source, "--plan", plan, "-o", self.root / "mismatch.zip")
        self.assertEqual(mismatch.returncode, 2)
        matched = self.run_cli(
            "pack", source, "--plan", plan, "--profile", "public", "-o", self.root / "matched.zip"
        )
        self.assertEqual(matched.returncode, 0, matched.stderr)

    def test_plan_payload_and_embedded_report_are_bounded(self) -> None:
        source = self.source()
        plan = create_plan(source)
        with (
            mock.patch("sharelint.documents.MAX_DOCUMENT_BYTES", 32),
            self.assertRaises(DocumentInputError),
        ):
            validate_plan(plan.payload)
        doc = copy.deepcopy(plan.document)
        doc["policy"]["limits"]["max_file_bytes"] = True
        with self.assertRaises(DocumentInputError):
            validate_plan(json.dumps(doc).encode())

    def test_receipt_does_not_repeat_matched_filename_evidence(self) -> None:
        source = self.root / "person@example.test.txt"
        source.write_text("ordinary synthetic public text\n", encoding="utf-8")
        receipt = self.root / "private-receipt.json"
        pack(source, self.root / "bundle.zip", receipt=receipt, fail_on=Severity.CRITICAL)
        self.assertFalse(
            source.name in receipt.read_text(encoding="utf-8"),
            "receipt repeated synthetic matched filename evidence",
        )
