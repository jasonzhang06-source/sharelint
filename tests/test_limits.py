from __future__ import annotations

import math
import os
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import tests.bootstrap  # noqa: F401
from sharelint.filesystem import (
    bounded_directory_items,
    bounded_directory_tree,
    metadata_is_filesystem_link,
    metadata_is_reparse_point,
)
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

    def test_windows_reparse_metadata_is_detected_without_platform_specific_apis(self) -> None:
        ordinary = SimpleNamespace(st_file_attributes=0, st_mode=stat.S_IFREG)
        reparse = SimpleNamespace(
            st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT,
            st_mode=stat.S_IFDIR,
        )
        symbolic_link = SimpleNamespace(st_mode=stat.S_IFLNK)
        posix_style = SimpleNamespace(st_mode=stat.S_IFREG)

        self.assertFalse(metadata_is_reparse_point(ordinary))  # type: ignore[arg-type]
        self.assertTrue(metadata_is_reparse_point(reparse))  # type: ignore[arg-type]
        self.assertFalse(metadata_is_reparse_point(posix_style))  # type: ignore[arg-type]
        self.assertFalse(metadata_is_filesystem_link(ordinary))  # type: ignore[arg-type]
        self.assertTrue(metadata_is_filesystem_link(reparse))  # type: ignore[arg-type]
        self.assertTrue(metadata_is_filesystem_link(symbolic_link))  # type: ignore[arg-type]

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

    def test_bounded_tree_returns_real_directories_without_following_links(self) -> None:
        with tempfile.TemporaryDirectory(prefix="sharelint-tree-") as directory:
            root = Path(directory)
            nested = root / "nested"
            nested.mkdir()
            payload = nested / "payload.txt"
            payload.write_text("synthetic content\n", encoding="utf-8")
            link_path = root / "linked"
            try:
                link_path.symlink_to(nested, target_is_directory=True)
                link: Path | None = link_path
            except OSError:
                link = None

            items, directories, errors, limited = bounded_directory_tree(root, 20)

            self.assertEqual(errors, 0)
            self.assertFalse(limited)
            self.assertEqual(directories, [nested])
            self.assertIn(payload, items)
            if link is not None:
                self.assertIn(link, items)

    def test_single_directory_enumeration_stops_at_the_global_entry_limit(self) -> None:
        class SyntheticEntry:
            def __init__(self, index: int) -> None:
                self.name = f"entry-{index}.txt"
                self.path = f"entry-{index}.txt"

            def is_dir(self, *, follow_symlinks: bool) -> bool:
                self.follow_symlinks = follow_symlinks
                return False

            def stat(self, *, follow_symlinks: bool) -> SimpleNamespace:
                self.follow_symlinks = follow_symlinks
                return SimpleNamespace(st_file_attributes=0, st_mode=stat.S_IFREG)

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

        with (
            tempfile.TemporaryDirectory(prefix="sharelint-bounded-enumeration-") as directory,
            patch("sharelint.filesystem.os.scandir", return_value=SyntheticScandir()),
        ):
            items, errors, limited = bounded_directory_items(Path(directory), 1)

        self.assertEqual(SyntheticScandir.pulls, 2)
        self.assertEqual(items, [])
        self.assertEqual(errors, 0)
        self.assertTrue(limited)

    def test_bounded_tree_rejects_a_directory_identity_change_before_recursing(self) -> None:
        with tempfile.TemporaryDirectory(prefix="sharelint-tree-identity-") as directory:
            root = Path(directory)
            nested = root / "nested"
            nested.mkdir()
            (nested / "payload.txt").write_text("synthetic content\n", encoding="utf-8")
            original_stat = Path.stat
            nested_checks = 0

            def changed_identity(path: Path, *, follow_symlinks: bool = True) -> os.stat_result:
                nonlocal nested_checks
                metadata = original_stat(path, follow_symlinks=follow_symlinks)
                if path == nested and not follow_symlinks:
                    nested_checks += 1
                    if nested_checks >= 2:
                        values = list(metadata)
                        values[1] += 1
                        return os.stat_result(values)
                return metadata

            with patch.object(Path, "stat", changed_identity):
                items, directories, errors, limited = bounded_directory_tree(root, 20)

        self.assertEqual(items, [])
        self.assertEqual(directories, [nested])
        self.assertEqual(errors, 1)
        self.assertFalse(limited)

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
