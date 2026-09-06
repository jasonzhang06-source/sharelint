from __future__ import annotations

import copy
import hashlib
import io
import json
import stat
import zipfile
from pathlib import Path
from typing import Any

import tests.bootstrap  # noqa: F401
from sharelint.documents import parse_json, validate_report
from sharelint.input_io import DocumentInputError
from sharelint.models import ScanLimits
from sharelint.packing import pack
from sharelint.reporters import render_json
from sharelint.scanner import scan
from sharelint.verification import (
    VerificationError,
    _archive_manifest,
    validate_receipt,
    verify_receipt,
)
from tests.cli_harness import CliTestCase


class VerificationTests(CliTestCase):
    def make_pack(self) -> tuple[Path, Path, Path]:
        source = self.root / "公开.txt"
        source.write_text("ordinary synthetic public content\n", encoding="utf-8")
        bundle = self.root / "bundle.zip"
        receipt = self.root / "receipt.json"
        report = self.root / "report.json"
        pack(source, bundle, receipt=receipt, report_output=report)
        return bundle, receipt, report

    def write_json(self, path: Path, value: Any) -> None:
        path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")

    def test_offline_verification_in_api_and_cli(self) -> None:
        bundle, receipt, report = self.make_pack()
        expected = hashlib.sha256(receipt.read_bytes()).hexdigest()
        verified = verify_receipt(receipt, report, bundle, expected_receipt_sha256=expected)
        self.assertEqual(verified.status, "verified")
        self.assertEqual(verified.file_count, 1)
        self.assertIn("expected-receipt-digest", verified.checks)
        result = self.run_cli(
            "verify", bundle, "--receipt", receipt, "--report", report, "--format", "json"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.json()["status"], "verified")
        self.assertNotIn("公开", result.stdout)
        self.assertNotIn(str(self.root), result.stdout)
        console = self.run_cli("verify", bundle, "--receipt", receipt, "--report", report)
        self.assertIn("no signature", console.stdout)

    def test_report_bytes_are_bound_including_whitespace(self) -> None:
        bundle, receipt, report = self.make_pack()
        report.write_bytes(report.read_bytes() + b"\n")
        result = self.run_cli(
            "verify", bundle, "--receipt", receipt, "--report", report, "--format", "json"
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.json()["status"], "mismatch")

    def test_artifact_mutation_and_expected_receipt_digest_are_rejected(self) -> None:
        bundle, receipt, report = self.make_pack()
        with self.assertRaises(VerificationError):
            verify_receipt(receipt, report, bundle, expected_receipt_sha256="0" * 64)
        bundle.write_bytes(bundle.read_bytes() + b"tampered")
        with self.assertRaises(VerificationError):
            verify_receipt(receipt, report, bundle)

    def test_manifest_and_policy_tampering_are_rejected(self) -> None:
        bundle, receipt, report = self.make_pack()
        original = json.loads(receipt.read_bytes())
        altered = copy.deepcopy(original)
        altered["files"][0]["sha256"] = "0" * 64
        self.write_json(receipt, altered)
        with self.assertRaises(VerificationError):
            verify_receipt(receipt, report, bundle)
        altered = copy.deepcopy(original)
        altered["policy"]["fail_on"] = "critical"
        self.write_json(receipt, altered)
        with self.assertRaises(VerificationError):
            verify_receipt(receipt, report, bundle)
        altered = copy.deepcopy(original)
        altered["tool"]["version"] = "999.0.0"
        self.write_json(receipt, altered)
        with self.assertRaises(VerificationError):
            verify_receipt(receipt, report, bundle)

    def test_verifier_limits_are_not_taken_from_receipt(self) -> None:
        bundle, receipt, report = self.make_pack()
        with self.assertRaises(DocumentInputError):
            verify_receipt(receipt, report, bundle, limits=ScanLimits(max_file_bytes=10))
        with self.assertRaises(VerificationError):
            verify_receipt(receipt, report, bundle, limits=ScanLimits(max_member_bytes=2))
        config = self.root / "limits.toml"
        config.write_text("schema_version = 1\n[limits]\nmax_file_bytes = 10\n", encoding="utf-8")
        result = self.run_cli(
            "verify", bundle, "--receipt", receipt, "--report", report, "--config", config
        )
        self.assertEqual(result.returncode, 2)

    def test_blocked_receipts_never_become_a_successful_pack(self) -> None:
        source = self.root / "document.pdf"
        source.write_bytes(b"%PDF-1.4\n%%EOF")
        receipt = self.root / "blocked.json"
        report = self.root / "blocked.report.json"
        blocked = self.run_cli(
            "pack", source, "-o", self.root / "absent.zip", "--receipt", receipt, "--report", report
        )
        self.assertEqual(blocked.returncode, 1, blocked.stderr)
        verified = self.run_cli(
            "verify", "--receipt", receipt, "--report", report, "--format", "json"
        )
        self.assertEqual(verified.returncode, 1, verified.stderr)
        self.assertEqual(verified.json()["status"], "blocked")
        with self.assertRaises(DocumentInputError):
            verify_receipt(receipt, report, source)

    def test_untrusted_text_is_never_echoed_by_verification(self) -> None:
        bundle, receipt, report = self.make_pack()
        doc = json.loads(report.read_bytes())
        doc["scan"]["target"]["name"] = "PRIVATE_MARKER\u001b[31m"
        doc["surfaces"][0]["note"] = "PRIVATE_MARKER"
        self.write_json(report, doc)
        rec = json.loads(receipt.read_bytes())
        rec["report_sha256"] = hashlib.sha256(report.read_bytes()).hexdigest()
        rec["claim"] = "PRIVATE_MARKER"
        self.write_json(receipt, rec)
        result = self.run_cli("verify", bundle, "--receipt", receipt, "--report", report)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("PRIVATE_MARKER", result.stdout + result.stderr)

    def test_receipt_structure_rejects_unknown_fields_and_bad_types(self) -> None:
        _, receipt, _ = self.make_pack()
        original = json.loads(receipt.read_bytes())
        cases = []
        for key, value in (
            ("schema_version", "2.0.0"),
            ("unexpected", "PRIVATE_MARKER"),
            ("created_at", "2026-90-01T10:00:00Z"),
            ("reasons", ["coverage_incomplete"]),
            ("status", "safe"),
            ("files", [{"path": "../escape", "size": 0, "sha256": "0" * 64}]),
        ):
            modified = copy.deepcopy(original)
            modified[key] = value
            cases.append(modified)
        modified = copy.deepcopy(original)
        modified["verification"]["coverage_complete"] = 1
        cases.append(modified)
        modified = copy.deepcopy(original)
        modified["archive"]["size"] = True
        cases.append(modified)
        for value in cases:
            with self.subTest(index=cases.index(value)), self.assertRaises(DocumentInputError):
                validate_receipt(json.dumps(value).encode())

    def test_report_summary_is_recomputed_not_trusted(self) -> None:
        _, _, report = self.make_pack()
        original = json.loads(report.read_bytes())
        for key, value in (
            ("surface_count", 0),
            ("blocking_findings", True),
            ("coverage_complete", False),
            ("verdict", "safe"),
        ):
            modified = copy.deepcopy(original)
            modified["summary"][key] = value
            with self.subTest(key=key), self.assertRaises(DocumentInputError):
                validate_report(json.dumps(modified).encode())
        original["future_extension"] = {"hint": "ignored"}
        parsed, _ = validate_report(json.dumps(original).encode())
        self.assertTrue(parsed.surfaces)
        original["summary"]["surfaces_by_status"]["unknown"] = 1
        with self.assertRaises(DocumentInputError):
            validate_report(json.dumps(original).encode())

    def test_native_findings_and_errors_roundtrip(self) -> None:
        source = self.root / "synthetic.txt"
        source.write_text("contact: person@example.test\n", encoding="utf-8")
        report = scan(source)
        self.assertTrue(report.findings)
        parsed, threshold = validate_report(render_json(report).encode())
        self.assertEqual(parsed.to_dict(threshold), report.to_dict(threshold))
        source.write_bytes(b"%PDF-1.4\n%%EOF")
        report = scan(source, limits=ScanLimits(max_file_bytes=2))
        parsed, _ = validate_report(render_json(report).encode())
        self.assertTrue(parsed.has_coverage_gaps)

    def test_json_parser_rejects_duplicates_nonfinite_depth_and_surrogates(self) -> None:
        cases = (
            b'{"a":1,"a":2}',
            b'{"a":NaN}',
            b'{"a":1e999}',
            b'{"a":"\\ud800"}',
            b"[" * 40 + b"0" + b"]" * 40,
            b"\xff",
            b"[]",
            b'{"a":',
            b'{"a":' + b"9" * 5000 + b"}",
        )
        for data in cases:
            with self.subTest(index=cases.index(data)), self.assertRaises(DocumentInputError):
                parse_json(data)
        self.assertEqual(parse_json(b'{"a":"[\\"{]"}')["a"], '["{]')

    def test_missing_artifact_and_malformed_receipt_exit_two(self) -> None:
        _, receipt, report = self.make_pack()
        result = self.run_cli("verify", "--receipt", receipt, "--report", report)
        self.assertEqual(result.returncode, 2)
        receipt.write_text("PRIVATE_MARKER not JSON", encoding="utf-8")
        result = self.run_cli("verify", "--receipt", receipt, "--report", report)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("PRIVATE_MARKER", result.stderr)

    def test_zip_members_are_bounded_and_never_extracted(self) -> None:
        for name, mode in (
            ("../escape", stat.S_IFREG),
            ("link", stat.S_IFLNK),
            ("folder/", stat.S_IFDIR),
        ):
            stream = io.BytesIO()
            with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                info = zipfile.ZipInfo(name)
                info.external_attr = (mode | 0o644) << 16
                archive.writestr(info, b"synthetic", compress_type=zipfile.ZIP_DEFLATED)
            with self.subTest(name=name), self.assertRaises(VerificationError):
                _archive_manifest(stream.getvalue(), ScanLimits())
        with self.assertRaises(VerificationError):
            _archive_manifest(b"not a zip", ScanLimits())

    def test_nested_type_mutations_fail_safely_without_uncaught_exceptions(self) -> None:
        _, receipt, report = self.make_pack()
        replacements = (None, True, False, -1, 0, 1, 1.5, [], {}, "", "PRIVATE_MARKER")

        def collect(value: Any, prefix: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
            paths: list[tuple[Any, ...]] = []
            entries = (
                value.items()
                if isinstance(value, dict)
                else enumerate(value)
                if isinstance(value, list)
                else ()
            )
            for key, child in entries:
                paths.append((*prefix, key))
                paths.extend(collect(child, (*prefix, key)))
            return paths

        for path, validator in ((receipt, validate_receipt), (report, validate_report)):
            original = json.loads(path.read_bytes())
            for keys in collect(original):
                for replacement in replacements:
                    modified = copy.deepcopy(original)
                    parent = modified
                    for key in keys[:-1]:
                        parent = parent[key]
                    parent[keys[-1]] = replacement
                    with self.subTest(
                        document=path.name, field=keys, replacement=repr(replacement)
                    ):
                        try:
                            validator(json.dumps(modified).encode())
                        except DocumentInputError as exc:
                            self.assertNotIn("PRIVATE_MARKER", str(exc))

    def test_archive_compression_total_and_member_count_limits(self) -> None:
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            for name in ("a.txt", "b.txt"):
                info = zipfile.ZipInfo(name)
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                archive.writestr(info, b"abc" * 100, compress_type=zipfile.ZIP_DEFLATED)
        for limits in (
            ScanLimits(max_archive_members=1),
            ScanLimits(max_total_bytes=400),
            ScanLimits(max_compression_ratio=1),
        ):
            with self.subTest(limits=limits), self.assertRaises(VerificationError):
                _archive_manifest(stream.getvalue(), limits)
