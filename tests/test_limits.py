from __future__ import annotations

import math
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import tests.bootstrap  # noqa: F401
from sharelint.filesystem import bounded_directory_items
from sharelint.models import ScanLimits
from sharelint.scanner import scan
from tests.helpers import write_zip


class ScanLimitTests(unittest.TestCase):
    def test_default_limits_are_finite_and_positive(self) -> None:
        limits = ScanLimits()
        self.assertGreater(limits.max_total_bytes, limits.max_file_bytes)
        self.assertTrue(math.isfinite(limits.max_compression_ratio))

    def test_invalid_limits_are_rejected_before_scanning(self) -> None:
        cases = (
            {"max_file_bytes": 0},
            {"max_member_bytes": -1},
            {"max_total_bytes": 0},
            {"max_archive_depth": 0},
            {"max_archive_members": 0},
            {"max_text_chars": 0},
            {"max_xml_elements": 0},
            {"max_findings": 0},
            {"max_compression_ratio": 0.0},
            {"max_compression_ratio": float("inf")},
            {"max_compression_ratio": float("nan")},
        )
        for overrides in cases:
            with self.subTest(overrides=overrides), self.assertRaises(ValueError):
                ScanLimits(**overrides)

    def test_filesystem_entry_limit_is_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="sharelint-limits-") as directory:
            root = Path(directory)
            (root / "first.txt").write_text("public first\n", encoding="utf-8")
            (root / "second.txt").write_text("public second\n", encoding="utf-8")

            report = scan(root, limits=ScanLimits(max_archive_members=1))

        self.assertTrue(report.has_coverage_gaps)
        self.assertEqual(report.summary()["verdict"], "incomplete")
        self.assertTrue(
            any(finding.rule_id == "SL.ARCHIVE.LIMIT_EXCEEDED" for finding in report.findings)
        )

    def test_single_directory_enumeration_stops_at_the_global_entry_limit(self) -> None:
        class SyntheticEntry:
            def __init__(self, index: int) -> None:
                self.name = f"entry-{index}.txt"
                self.path = f"/synthetic/entry-{index}.txt"

            def is_dir(self, *, follow_symlinks: bool) -> bool:
                self.follow_symlinks = follow_symlinks
                return False

        class SyntheticScandir:
            pulls = 0

            def __enter__(self) -> SyntheticScandir:
                return self

            def __exit__(self, *_args: object) -> None:
                return None

            def __iter__(self) -> SyntheticScandir:
                return self

            def __next__(self) -> SyntheticEntry:
                type(self).pulls += 1
                if type(self).pulls > 100:
                    raise AssertionError(
                        "bounded enumeration exhausted an attacker-sized directory"
                    )
                return SyntheticEntry(type(self).pulls)

        with patch("sharelint.filesystem.os.scandir", return_value=SyntheticScandir()):
            items, errors, limited = bounded_directory_items(Path("/synthetic"), 1)

        self.assertEqual(SyntheticScandir.pulls, 2)
        self.assertEqual(items, [])
        self.assertEqual(errors, 0)
        self.assertTrue(limited)

    def test_ooxml_element_limit_is_an_explicit_coverage_gap(self) -> None:
        with tempfile.TemporaryDirectory(prefix="sharelint-limits-") as directory:
            target = Path(directory) / "element-heavy.docx"
            document = (
                '<w:document xmlns:w="http://schemas.openxmlformats.org/'
                'wordprocessingml/2006/main"><w:body>' + "<w:p/>" * 12 + "</w:body></w:document>"
            )
            write_zip(target, {"word/document.xml": document})

            report = scan(target, limits=ScanLimits(max_xml_elements=5))

        self.assertEqual(report.limits.max_xml_elements, 5)
        self.assertTrue(report.has_coverage_gaps)
        self.assertEqual(report.summary()["verdict"], "incomplete")
        self.assertTrue(
            any(
                finding.rule_id == "SL.ARCHIVE.LIMIT_EXCEEDED"
                and finding.location == "OOXML XML element count"
                for finding in report.findings
            )
        )
        self.assertTrue(
            any(
                surface.kind == "ooxml-xml"
                and surface.status.value == "partial"
                and "element-count" in surface.note
                for surface in report.surfaces
            )
        )

    def test_svg_text_limit_is_an_explicit_coverage_gap(self) -> None:
        with tempfile.TemporaryDirectory(prefix="sharelint-limits-") as directory:
            target = Path(directory) / "large.svg"
            target.write_text("<svg>" + "a" * 128 + "</svg>", encoding="utf-8")

            report = scan(target, limits=ScanLimits(max_text_chars=32))

        self.assertTrue(report.has_coverage_gaps)
        self.assertEqual(report.summary()["verdict"], "incomplete")
        self.assertTrue(
            any(
                surface.kind == "svg" and surface.status.value == "partial"
                for surface in report.surfaces
            )
        )


if __name__ == "__main__":
    unittest.main()
