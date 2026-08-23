from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path, PurePosixPath
from typing import Any
from unittest.mock import patch
from zipfile import ZipFile

import tests.bootstrap  # noqa: F401
from sharelint import packing as packing_module
from sharelint.packing import PackError, pack
from tests.cli_harness import CliTestCase
from tests.helpers import FICTIONAL_SECRET, sha256_file, write_jpeg, write_traversal_zip


def _manifest(receipt: dict[str, Any]) -> list[dict[str, Any]]:
    value = receipt.get("files")
    if value is None and isinstance(receipt.get("manifest"), dict):
        value = receipt["manifest"].get("files")
    assert isinstance(value, list), "receipt needs a content-addressed files manifest"
    assert all(isinstance(item, dict) for item in value)
    return value


def _archive_sha256(receipt: dict[str, Any]) -> str | None:
    for key in ("archive_sha256", "output_sha256"):
        value = receipt.get(key)
        if isinstance(value, str):
            return value
    archive = receipt.get("archive")
    if isinstance(archive, dict):
        value = archive.get("sha256")
        if isinstance(value, str):
            return value
    return None


def _report_path(receipt: Path) -> Path:
    if receipt.name.endswith(".json"):
        return receipt.with_name(f"{receipt.name[:-5]}.report.json")
    return Path(f"{receipt}.report.json")


class PackReceiptTests(CliTestCase):
    def test_pack_does_not_offer_an_allow_partial_policy_bypass(self) -> None:
        help_result = self.run_cli("pack", "--help")
        self.assertEqual(help_result.returncode, 0)
        self.assertNotIn("--allow-partial", help_result.stdout + help_result.stderr)

        partial = write_jpeg(
            self.root / "partial.jpg",
            description="",
            artist="",
        )
        output = self.root / "must-not-pack.zip"
        result = self.run_cli("pack", partial, "-o", output, "--allow-partial")

        self.assertEqual(result.returncode, 2)
        self.assertFalse(output.exists())
        self.assertFalse(self.root.joinpath("must-not-pack.zip.sharelint.json").exists())

    def test_pack_writes_deterministic_archive_and_verifiable_receipt(self) -> None:
        source = self.root / "source"
        (source / "nested").mkdir(parents=True)
        (source / "z-last.txt").write_text("public synthetic z\n", encoding="utf-8")
        (source / "nested" / "a-first.txt").write_text(
            "public synthetic a\n",
            encoding="utf-8",
        )
        first_zip = self.root / "first.zip"
        second_zip = self.root / "second.zip"
        first_receipt = self.root / "first-receipt.json"
        second_receipt = self.root / "second-receipt.json"

        first = self.run_cli("pack", source, "-o", first_zip, "--receipt", first_receipt)
        second = self.run_cli("pack", source, "-o", second_zip, "--receipt", second_receipt)

        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertTrue(first_zip.is_file() and second_zip.is_file())
        self.assertTrue(first_receipt.is_file() and second_receipt.is_file())
        self.assertTrue(_report_path(first_receipt).is_file())
        self.assertTrue(_report_path(second_receipt).is_file())
        self.assertEqual(first_zip.read_bytes(), second_zip.read_bytes())

        with ZipFile(first_zip) as archive:
            infos = archive.infolist()
            names = [item.filename for item in infos]
            self.assertEqual(names, sorted(names))
            self.assertEqual(names, ["nested/a-first.txt", "z-last.txt"])
            self.assertEqual(len({item.date_time for item in infos}), 1)
            self.assertTrue(
                all(
                    not PurePosixPath(name).is_absolute() and ".." not in PurePosixPath(name).parts
                    for name in names
                )
            )

        receipts = [
            json.loads(first_receipt.read_text(encoding="utf-8")),
            json.loads(second_receipt.read_text(encoding="utf-8")),
        ]
        for receipt, receipt_path, bundle in zip(
            receipts,
            (first_receipt, second_receipt),
            (first_zip, second_zip),
            strict=True,
        ):
            self.assertEqual(receipt.get("schema_version"), "1.0.0")
            self.assertEqual(receipt.get("status"), "packed")
            report_bytes = _report_path(receipt_path).read_bytes()
            self.assertEqual(
                receipt.get("report_sha256"),
                hashlib.sha256(report_bytes).hexdigest(),
            )
            report_document = json.loads(report_bytes)
            self.assertEqual(report_document.get("schema_version"), "1.0.0")
            self.assertIsInstance(report_document.get("findings"), list)
            self.assertIsInstance(report_document.get("surfaces"), list)
            manifest = _manifest(receipt)
            self.assertEqual([item.get("path") for item in manifest], names)
            for item in manifest:
                expected = (source / item["path"]).read_bytes()
                self.assertEqual(item.get("size"), len(expected))
                self.assertEqual(
                    item.get("sha256"),
                    hashlib.sha256(expected).hexdigest(),
                )
            self.assertEqual(_archive_sha256(receipt), sha256_file(bundle))
            serialized = json.dumps(receipt, sort_keys=True)
            self.assert_omits(str(self.root), serialized)
            self.assert_omits(FICTIONAL_SECRET, serialized)

        self.assertEqual(_manifest(receipts[0]), _manifest(receipts[1]))
        self.assertEqual(_archive_sha256(receipts[0]), _archive_sha256(receipts[1]))

    def test_blocked_pack_writes_requested_rejection_receipt_without_artifact(self) -> None:
        source = self.root / "source"
        source.mkdir()
        write_traversal_zip(source / "hostile.zip")
        (source / "credentials.txt").write_text(FICTIONAL_SECRET, encoding="utf-8")
        output = self.root / "must-not-exist.zip"
        receipt_path = self.root / "blocked-receipt.json"

        result = self.run_cli("pack", source, "-o", output, "--receipt", receipt_path)

        self.assertEqual(result.returncode, 1)
        self.assertFalse(output.exists(), "a blocked pack must not leave a partial archive")
        self.assertTrue(
            receipt_path.is_file(),
            "an explicitly requested receipt must record why packing was refused",
        )
        report_path = _report_path(receipt_path)
        self.assertTrue(
            report_path.is_file(),
            "an explicitly requested blocked receipt needs its hash-bound scan report",
        )
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        self.assertEqual(receipt.get("schema_version"), "1.0.0")
        self.assertEqual(receipt.get("status"), "blocked")
        self.assertIsInstance(receipt.get("source"), dict)
        self.assertIsInstance(receipt.get("policy"), dict)
        self.assertIsInstance(receipt.get("summary"), dict)
        self.assertGreater(receipt["summary"].get("blocking_findings", 0), 0)
        report_sha256 = receipt.get("report_sha256")
        self.assertIsInstance(report_sha256, str)
        self.assertEqual(len(report_sha256), 64)
        int(report_sha256, 16)
        report_bytes = report_path.read_bytes()
        self.assertEqual(report_sha256, hashlib.sha256(report_bytes).hexdigest())
        report_document = json.loads(report_bytes)
        self.assertIn(
            report_document.get("summary", {}).get("verdict"),
            {"blocked", "incomplete"},
        )
        self.assertGreater(report_document.get("summary", {}).get("total_findings", 0), 0)
        reasons = receipt.get("reasons")
        self.assertIsInstance(reasons, list)
        self.assertTrue(reasons)
        self.assertIn("blocking_findings", reasons)
        for prohibited_key in (
            "archive",
            "files",
            "findings",
            "masked_preview",
            "source_chain",
            "verification",
        ):
            if prohibited_key in receipt:
                self.fail(
                    f"blocked receipt contained prohibited key {prohibited_key!r}; document omitted"
                )
        serialized = json.dumps(receipt, sort_keys=True)
        if "masked_preview" in serialized:
            self.fail("blocked receipt exposed masked-preview structures; document omitted")
        self.assert_omits(FICTIONAL_SECRET, serialized)
        self.assert_omits(str(self.root), serialized)
        combined_output = result.stdout + result.stderr
        self.assert_omits(FICTIONAL_SECRET, result.stdout, result.stderr)
        self.assertNotIn("traceback", combined_output.lower())

    def test_blocked_pack_without_explicit_receipt_writes_no_evidence_files(self) -> None:
        source = self.root / "blocked-source.txt"
        source.write_text(FICTIONAL_SECRET, encoding="utf-8")
        output = self.root / "must-not-exist.zip"
        receipt_path = Path(f"{output}.sharelint.json")
        report_path = _report_path(receipt_path)

        result = self.run_cli("pack", source, "-o", output)

        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertFalse(output.exists())
        self.assertFalse(receipt_path.exists())
        self.assertFalse(report_path.exists())
        self.assertNotIn("traceback", (result.stdout + result.stderr).lower())

    def test_no_receipt_writes_only_the_archive(self) -> None:
        source = self.root / "public.txt"
        source.write_text("public synthetic material\n", encoding="utf-8")
        output = self.root / "public.zip"
        receipt_path = Path(f"{output}.sharelint.json")
        report_path = _report_path(receipt_path)

        result = self.run_cli("pack", source, "-o", output, "--no-receipt")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(output.is_file())
        self.assertFalse(receipt_path.exists())
        self.assertFalse(report_path.exists())

    def test_explicit_report_path_is_hash_bound_to_the_receipt(self) -> None:
        source = self.root / "public.txt"
        source.write_text("public synthetic material\n", encoding="utf-8")
        output = self.root / "public.zip"
        receipt = self.root / "receipt.json"
        report = self.root / "custom-report.json"

        result = self.run_cli(
            "pack",
            source,
            "-o",
            output,
            "--receipt",
            receipt,
            "--report",
            report,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(output.is_file())
        self.assertTrue(receipt.is_file())
        self.assertTrue(report.is_file())
        receipt_document = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertEqual(
            receipt_document.get("report_sha256"),
            hashlib.sha256(report.read_bytes()).hexdigest(),
        )
        self.assertFalse(_report_path(receipt).exists())

    def test_explicit_report_requires_explicit_receipt(self) -> None:
        source = self.root / "public.txt"
        source.write_text("public synthetic material\n", encoding="utf-8")
        output = self.root / "public.zip"
        report = self.root / "custom-report.json"

        result = self.run_cli("pack", source, "-o", output, "--report", report)

        self.assertEqual(result.returncode, 2)
        self.assertFalse(output.exists())
        self.assertFalse(report.exists())
        self.assertIn("--report requires an explicit --receipt", result.stderr)
        self.assertNotIn("traceback", (result.stdout + result.stderr).lower())

    def test_pack_refuses_to_overwrite_output_receipt_or_companion_report(self) -> None:
        source = self.root / "public.txt"
        source.write_text("public synthetic material\n", encoding="utf-8")
        sentinel = b"FICTITIOUS_EXISTING_ARTIFACT\n"

        output_existing = self.root / "existing-output.zip"
        output_existing.write_bytes(sentinel)
        output_receipt = self.root / "output-receipt.json"
        results = []
        result = self.run_cli("pack", source, "-o", output_existing, "--receipt", output_receipt)
        results.append(result)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(output_existing.read_bytes(), sentinel)
        self.assertFalse(output_receipt.exists())
        self.assertFalse(_report_path(output_receipt).exists())

        receipt_existing = self.root / "existing-receipt.json"
        receipt_existing.write_bytes(sentinel)
        receipt_output = self.root / "receipt-output.zip"
        result = self.run_cli("pack", source, "-o", receipt_output, "--receipt", receipt_existing)
        results.append(result)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse(receipt_output.exists())
        self.assertEqual(receipt_existing.read_bytes(), sentinel)
        self.assertFalse(_report_path(receipt_existing).exists())

        report_receipt = self.root / "report-receipt.json"
        report_existing = _report_path(report_receipt)
        report_existing.write_bytes(sentinel)
        report_output = self.root / "report-output.zip"
        result = self.run_cli("pack", source, "-o", report_output, "--receipt", report_receipt)
        results.append(result)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse(report_output.exists())
        self.assertFalse(report_receipt.exists())
        self.assertEqual(report_existing.read_bytes(), sentinel)

        for result in results:
            self.assertNotIn("traceback", (result.stdout + result.stderr).lower())

    def test_cleanup_never_deletes_concurrent_replacements_after_inode_reuse(self) -> None:
        source = self.root / "public.txt"
        source.write_text("public synthetic material\n", encoding="utf-8")
        output = self.root / "bundle.zip"
        receipt = self.root / "receipt.json"
        report = _report_path(receipt)
        output_replacement = b"FICTITIOUS_CONCURRENT_OUTPUT\n"
        report_replacement = b"FICTITIOUS_CONCURRENT_REPORT\n"

        def replace_published_files(_path: Path, _document: dict[str, Any]):
            output.unlink()
            output.write_bytes(output_replacement)
            report.unlink()
            report.write_bytes(report_replacement)
            raise PackError("synthetic receipt write failure")

        with (
            patch.object(packing_module, "_write_document", side_effect=replace_published_files),
            self.assertRaises(PackError),
        ):
            pack(source, output, receipt=receipt)

        self.assertEqual(output.read_bytes(), output_replacement)
        self.assertEqual(report.read_bytes(), report_replacement)
        self.assertFalse(receipt.exists())

    def test_commit_rejects_concurrent_replacements_instead_of_returning_success(self) -> None:
        source = self.root / "public.txt"
        source.write_text("public synthetic material\n", encoding="utf-8")
        output = self.root / "bundle.zip"
        receipt = self.root / "receipt.json"
        report = _report_path(receipt)
        output_replacement = b"FICTITIOUS_POST_PUBLISH_OUTPUT\n"
        report_replacement = b"FICTITIOUS_POST_PUBLISH_REPORT\n"
        original_write_document = packing_module._write_document

        def replace_before_commit(path: Path, document: dict[str, Any]):
            publication = original_write_document(path, document)
            output.unlink()
            output.write_bytes(output_replacement)
            report.unlink()
            report.write_bytes(report_replacement)
            return publication

        with (
            patch.object(packing_module, "_write_document", side_effect=replace_before_commit),
            self.assertRaisesRegex(PackError, "changed before the pack transaction committed"),
        ):
            pack(source, output, receipt=receipt)

        self.assertEqual(output.read_bytes(), output_replacement)
        self.assertEqual(report.read_bytes(), report_replacement)
        self.assertFalse(receipt.exists())


if __name__ == "__main__":
    unittest.main()
