from __future__ import annotations

import hashlib
import json
import os
import struct
import sys
import unittest
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

import tests.bootstrap  # noqa: F401
from sharelint.models import ScanLimits
from sharelint.reporters import render_json
from sharelint.scanner import scan
from tests.cli_harness import CliTestCase
from tests.contract import assert_scan_contract
from tests.helpers import FICTIONAL_SECRET, write_zip


def _write_malformed_docx(path: Path) -> Path:
    return write_zip(
        path,
        {
            "[Content_Types].xml": (
                '<?xml version="1.0" encoding="UTF-8"?>'
                '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                '<Default Extension="xml" ContentType="application/xml"/>'
                '<Override PartName="/word/document.xml" '
                'ContentType="application/vnd.openxmlformats-officedocument.'
                'wordprocessingml.document.main+xml"/>'
                "</Types>"
            ),
            "_rels/.rels": (
                '<?xml version="1.0" encoding="UTF-8"?>'
                '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/'
                'relationships"><Relationship Id="rId1" '
                'Type="http://schemas.openxmlformats.org/officeDocument/2006/'
                'relationships/officeDocument" Target="word/document.xml"/>'
                "</Relationships>"
            ),
            "word/document.xml": (
                '<w:document xmlns:w="http://schemas.openxmlformats.org/'
                'wordprocessingml/2006/main"><w:body><w:p>'
            ),
        },
    )


def _write_corrupt_deflate_zip(path: Path) -> Path:
    write_zip(
        path,
        {
            "FICTITIOUS_CORRUPT_MEMBER.txt": bytes(range(256)) * 8,
        },
    )
    payload = bytearray(path.read_bytes())
    if payload[:4] != b"PK\x03\x04":
        raise AssertionError("fixture ZIP has no local file header")
    compressed_size = struct.unpack_from("<I", payload, 18)[0]
    filename_size, extra_size = struct.unpack_from("<HH", payload, 26)
    compressed_start = 30 + filename_size + extra_size
    if compressed_size < 3:
        raise AssertionError("fixture ZIP compressed stream is unexpectedly short")
    payload[compressed_start + compressed_size // 2] ^= 0xFF
    path.write_bytes(payload)
    return path


def _write_zip_with_comments(path: Path, archive_comment: bytes, entry_comment: bytes) -> Path:
    with ZipFile(path, "w", compression=ZIP_DEFLATED) as archive:
        info = ZipInfo("ordinary.txt", date_time=(1980, 1, 1, 0, 0, 0))
        info.compress_type = ZIP_DEFLATED
        info.comment = entry_comment
        archive.writestr(info, b"ordinary synthetic content\n")
        archive.comment = archive_comment
    return path


def _write_zip_with_unknown_extra(path: Path) -> Path:
    with ZipFile(path, "w", compression=ZIP_DEFLATED) as archive:
        info = ZipInfo("ordinary.txt", date_time=(1980, 1, 1, 0, 0, 0))
        info.compress_type = ZIP_DEFLATED
        info.extra = struct.pack("<HH", 0xCAFE, 4) + b"DEMO"
        archive.writestr(info, b"ordinary synthetic content\n")
    return path


def _all_strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _all_strings(key)
            yield from _all_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _all_strings(item)


class SecurityRegressionTests(CliTestCase):
    def test_zip_archive_and_entry_comments_are_scanned_as_shareable_bytes(self) -> None:
        assigned_secret = b"password=AbCdEf1234567890"
        archive = _write_zip_with_comments(
            self.root / "comments.zip",
            assigned_secret,
            FICTIONAL_SECRET.encode("ascii"),
        )

        scanned = self.run_cli("scan", archive, "--format", "json", "--strict")

        self.assertEqual(scanned.returncode, 1, scanned.stderr)
        payload = scanned.json()
        findings = assert_scan_contract(payload)
        self.assertTrue(payload["summary"]["coverage_complete"])
        self.assertTrue(
            {"SL.SECRET.GENERIC_ASSIGNMENT", "SL.SECRET.GITHUB_TOKEN"}
            <= {finding["rule_id"] for finding in findings}
        )
        self.assertTrue(any(surface["kind"] == "zip-comment" for surface in payload["surfaces"]))
        self.assertTrue(
            any(surface["kind"] == "zip-entry-comment" for surface in payload["surfaces"])
        )
        self.assertNotIn(assigned_secret.decode("ascii"), scanned.stdout)
        self.assertNotIn(FICTIONAL_SECRET, scanned.stdout)

    def test_unknown_zip_extra_fields_are_an_explicit_coverage_gap(self) -> None:
        archive = _write_zip_with_unknown_extra(self.root / "unknown-extra.zip")

        scanned = self.run_cli("scan", archive, "--format", "json", "--strict")

        self.assertEqual(scanned.returncode, 1, scanned.stderr)
        payload = scanned.json()
        assert_scan_contract(payload)
        self.assertEqual(payload["summary"]["verdict"], "incomplete")
        self.assertTrue(
            any(
                surface["kind"] == "zip-extra-fields" and surface["status"] == "partial"
                for surface in payload["surfaces"]
            )
        )

    def test_malformed_ooxml_is_an_explicit_coverage_gap_and_blocks_pack(self) -> None:
        document = _write_malformed_docx(self.root / "malformed.docx")

        report = scan(document)
        payload = json.loads(render_json(report))
        assert_scan_contract(payload)
        self.assertTrue(report.has_coverage_gaps)
        self.assertEqual(report.summary()["verdict"], "incomplete")
        self.assertTrue(
            any(
                error.code == "SL.SCAN.READ_ERROR" and "word/document.xml" in error.source_chain
                for error in report.errors
            ),
            "malformed OOXML must produce a content-free parser error",
        )
        self.assertTrue(
            any(
                surface.status.value in {"partial", "skipped"}
                and "word/document.xml" in surface.source_chain
                for surface in report.surfaces
            ),
            "malformed OOXML must identify the uninspected XML surface",
        )

        output = self.root / "must-not-pack.zip"
        packed = self.run_cli("pack", document, "-o", output)

        self.assertEqual(packed.returncode, 1, packed.stderr)
        self.assertFalse(output.exists())
        self.assertFalse(Path(f"{output}.sharelint.json").exists())
        self.assertFalse(Path(f"{output}.sharelint.report.json").exists())
        self.assertNotIn("traceback", (packed.stdout + packed.stderr).lower())

    def test_corrupt_deflate_zip_scan_and_pack_fail_closed_without_traceback(self) -> None:
        archive = _write_corrupt_deflate_zip(self.root / "corrupt-deflate.zip")

        scanned = self.run_cli("scan", archive, "--format", "json", "--strict")

        self.assertEqual(scanned.returncode, 1, scanned.stderr)
        payload = scanned.json()
        assert_scan_contract(payload)
        self.assertEqual(payload["summary"]["verdict"], "incomplete")
        self.assertGreater(payload["summary"]["error_count"], 0)
        self.assertTrue(
            any(error.get("code") == "SL.SCAN.READ_ERROR" for error in payload["errors"])
        )
        self.assertNotIn("traceback", (scanned.stdout + scanned.stderr).lower())

        output = self.root / "must-not-pack.zip"
        packed = self.run_cli("pack", archive, "-o", output)

        self.assertEqual(packed.returncode, 1, packed.stderr)
        self.assertFalse(output.exists())
        self.assertFalse(Path(f"{output}.sharelint.json").exists())
        self.assertFalse(Path(f"{output}.sharelint.report.json").exists())
        self.assertNotIn("traceback", (packed.stdout + packed.stderr).lower())

    def test_finding_limit_is_bounded_and_marks_report_incomplete(self) -> None:
        limit = 7
        source = self.root / "many-findings.txt"
        source.write_text(
            "\n".join(f"synthetic-{index}@example.invalid" for index in range(limit * 4)),
            encoding="utf-8",
        )

        report = scan(source, limits=ScanLimits(max_findings=limit))
        rendered = render_json(report)
        payload = json.loads(rendered)
        findings = assert_scan_contract(payload)

        self.assertLessEqual(len(findings), limit)
        self.assertGreater(len(findings), 0)
        self.assertEqual(payload["scan"]["limits"]["max_findings"], limit)
        self.assertEqual(payload["summary"]["verdict"], "incomplete")
        self.assertFalse(payload["summary"]["coverage_complete"])
        self.assertTrue(
            any(error.get("code") == "SL.ARCHIVE.LIMIT_EXCEEDED" for error in payload["errors"])
        )
        self.assertTrue(
            any(
                surface.get("kind") == "finding-ledger" and surface.get("status") == "partial"
                for surface in payload["surfaces"]
            )
        )
        rendered.encode("utf-8")

    @unittest.skipUnless(
        sys.platform.startswith("linux"),
        "arbitrary byte filenames require Linux surrogateescape",
    )
    def test_invalid_utf8_filename_is_json_safe_and_blocks_pack(self) -> None:
        source = self.root / "byte-names"
        source.mkdir()
        raw_path = os.fsencode(source) + b"/FICTITIOUS_INVALID_\xff.txt"
        descriptor = os.open(raw_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(b"public synthetic content\n")

        scanned = self.run_cli("scan", source, "--format", "json", "--strict")

        self.assertEqual(scanned.returncode, 1, scanned.stderr)
        payload = scanned.json()
        assert_scan_contract(payload)
        encoded = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.assertEqual(hashlib.sha256(encoded).digest_size, 32)
        self.assertFalse(
            any(
                0xD800 <= ord(character) <= 0xDFFF
                for value in _all_strings(payload)
                for character in value
            ),
            "JSON contract must not expose surrogate code points",
        )
        self.assertEqual(payload["summary"]["verdict"], "incomplete")
        self.assertNotIn("traceback", (scanned.stdout + scanned.stderr).lower())

        output = self.root / "must-not-pack.zip"
        packed = self.run_cli("pack", source, "-o", output)

        self.assertEqual(packed.returncode, 1, packed.stderr)
        self.assertFalse(output.exists())
        self.assertFalse(Path(f"{output}.sharelint.json").exists())
        self.assertFalse(Path(f"{output}.sharelint.report.json").exists())
        self.assertNotIn("traceback", (packed.stdout + packed.stderr).lower())


if __name__ == "__main__":
    unittest.main()
