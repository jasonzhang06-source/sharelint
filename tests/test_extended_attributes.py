from __future__ import annotations

import ctypes
import errno
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from zipfile import ZipFile

import tests.bootstrap  # noqa: F401
from sharelint import packing as packing_module
from sharelint.extended_attributes import (
    EXTENDED_ATTRIBUTE_ERROR_MESSAGE,
    ExtendedAttributeStatus,
    _linux_name_list_size,
    _macos_name_list_size,
    probe_extended_attributes,
)
from sharelint.models import ScanLimits, Severity
from sharelint.packing import PackBlocked, pack
from sharelint.rules import get_rule
from sharelint.scanner import scan


class _FakeXattrFunction:
    def __init__(self, result: int) -> None:
        self.result = result
        self.calls: list[tuple[object, ...]] = []
        self.argtypes: object = None
        self.restype: object = None

    def __call__(self, *arguments: object) -> int:
        self.calls.append(arguments)
        return self.result


class ExtendedAttributeTests(unittest.TestCase):
    def test_linux_probe_requests_only_the_name_list_size(self) -> None:
        function = _FakeXattrFunction(17)
        library = SimpleNamespace(llistxattr=function)

        with patch("sharelint.extended_attributes.ctypes.CDLL", return_value=library):
            result = _linux_name_list_size(Path("synthetic.txt"))

        self.assertEqual(result, 17)
        self.assertEqual(len(function.calls), 1)
        encoded_path, name_buffer, buffer_size = function.calls[0]
        self.assertEqual(encoded_path, os.fsencode("synthetic.txt"))
        self.assertIsNone(name_buffer)
        self.assertEqual(buffer_size, 0)

    def test_macos_probe_requests_only_the_name_list_size_without_following_links(self) -> None:
        function = _FakeXattrFunction(23)
        library = SimpleNamespace(listxattr=function)

        with patch("sharelint.extended_attributes.ctypes.CDLL", return_value=library):
            result = _macos_name_list_size(Path("synthetic.txt"))

        self.assertEqual(result, 23)
        self.assertEqual(len(function.calls), 1)
        encoded_path, name_buffer, buffer_size, options = function.calls[0]
        self.assertEqual(encoded_path, os.fsencode("synthetic.txt"))
        self.assertIsNone(name_buffer)
        self.assertEqual(buffer_size, 0)
        self.assertEqual(options, 0x0001)

    def test_probe_collapses_results_to_privacy_safe_states(self) -> None:
        cases = ((0, ExtendedAttributeStatus.ABSENT), (9, ExtendedAttributeStatus.PRESENT))
        for size, expected in cases:
            with (
                self.subTest(size=size),
                patch("sharelint.extended_attributes.sys.platform", "linux"),
                patch("sharelint.extended_attributes._linux_name_list_size", return_value=size),
            ):
                self.assertEqual(probe_extended_attributes(Path("synthetic.txt")), expected)

        with (
            patch("sharelint.extended_attributes.sys.platform", "linux"),
            patch("sharelint.extended_attributes._linux_name_list_size", return_value=-1),
        ):
            self.assertEqual(
                probe_extended_attributes(Path("synthetic.txt")),
                ExtendedAttributeStatus.ERROR,
            )

        with patch("sharelint.extended_attributes.sys.platform", "freebsd14"):
            self.assertEqual(
                probe_extended_attributes(Path("synthetic.txt")),
                ExtendedAttributeStatus.NOT_APPLICABLE,
            )

    @unittest.skipUnless(
        sys.platform.startswith("linux") and hasattr(os, "setxattr"),
        "native Linux extended attributes are unavailable",
    )
    def test_native_file_and_directory_attributes_are_detected_without_values(self) -> None:
        marker = b"FICTITIOUS_PRIVATE_XATTR_VALUE"
        with tempfile.TemporaryDirectory(prefix="sharelint-xattr-") as directory:
            root = Path(directory)
            target_file = root / "ordinary.txt"
            target_directory = root / "ordinary-directory"
            target_file.write_text("ordinary synthetic text\n", encoding="utf-8")
            target_directory.mkdir()
            try:
                os.setxattr(target_file, b"user.sharelint_test", marker, follow_symlinks=False)
                os.setxattr(target_directory, b"user.sharelint_test", marker, follow_symlinks=False)
            except OSError as error:
                unsupported = {
                    errno.EACCES,
                    errno.ENOTSUP,
                    errno.EOPNOTSUPP,
                    errno.EPERM,
                }
                if error.errno in unsupported:
                    self.skipTest("temporary filesystem does not permit user extended attributes")
                raise

            for target in (target_file, target_directory):
                with self.subTest(target_kind="directory" if target.is_dir() else "file"):
                    result = probe_extended_attributes(target)
                    self.assertEqual(result, ExtendedAttributeStatus.PRESENT)
                    self.assertNotIn(marker.decode("ascii"), repr(result))

    def test_rule_and_error_contract_are_fixed_and_blocking(self) -> None:
        rule = get_rule("SL.FILESYSTEM.EXTENDED_ATTRIBUTES")

        self.assertEqual(rule.severity, Severity.HIGH)
        self.assertIn("coverage", rule.tags)
        self.assertEqual(
            EXTENDED_ATTRIBUTE_ERROR_MESSAGE,
            "Extended attributes could not be enumerated",
        )

    @unittest.skipUnless(
        sys.platform.startswith("linux") or sys.platform == "darwin",
        "native extended attributes require Linux or macOS",
    )
    def test_scan_and_pack_fail_closed_for_file_and_nested_directory_attributes(self) -> None:
        attribute_name = b"user.sharelint.synthetic"
        if sys.platform == "darwin":
            attribute_name = b"com.example.sharelint.synthetic"
        attribute_value = b"FICTITIOUS_PRIVATE_XATTR_VALUE"
        with tempfile.TemporaryDirectory(prefix="sharelint-xattr-integration-") as directory:
            root = Path(directory) / "share-boundary"
            nested = root / "nested"
            nested.mkdir(parents=True)
            target_file = nested / "ordinary.txt"
            target_file.write_text("ordinary synthetic text\n", encoding="utf-8")
            for target in (nested, target_file):
                self._set_native_attribute(target, attribute_name, attribute_value)

            report = scan(root)
            serialized = json.dumps(report.to_dict(), sort_keys=True)

            findings = [
                finding
                for finding in report.findings
                if finding.rule_id == "SL.FILESYSTEM.EXTENDED_ATTRIBUTES"
            ]
            self.assertEqual(len(findings), 2)
            self.assertTrue(report.has_coverage_gaps)
            self.assertEqual(report.summary()["verdict"], "incomplete")
            self.assertNotIn(attribute_name.decode("ascii"), serialized)
            self.assertNotIn(attribute_value.decode("ascii"), serialized)

            output = Path(directory) / "must-not-exist.zip"
            with self.assertRaises(PackBlocked):
                pack(root, output, write_receipt=False)
            self.assertFalse(output.exists())

    @unittest.skipUnless(
        sys.platform.startswith("linux") or sys.platform == "darwin",
        "native extended attributes require Linux or macOS",
    )
    def test_attribute_added_during_pack_is_caught_by_the_final_source_scan(self) -> None:
        attribute_name = b"user.sharelint.changed"
        if sys.platform == "darwin":
            attribute_name = b"com.example.sharelint.changed"
        attribute_value = b"FICTITIOUS_LATE_XATTR_VALUE"
        with tempfile.TemporaryDirectory(prefix="sharelint-xattr-race-") as directory:
            source = Path(directory) / "public.txt"
            source.write_text("ordinary synthetic text\n", encoding="utf-8")
            output = Path(directory) / "must-not-exist.zip"
            original_write_source = packing_module._write_source

            def add_attribute_after_archive_write(
                archive: ZipFile,
                target: Path,
                limits: ScanLimits,
            ) -> packing_module._SourceWriteResult:
                files = original_write_source(archive, target, limits)
                self._set_native_attribute(source, attribute_name, attribute_value)
                return files

            with (
                patch.object(
                    packing_module,
                    "_write_source",
                    side_effect=add_attribute_after_archive_write,
                ),
                self.assertRaises(PackBlocked) as caught,
            ):
                pack(source, output, write_receipt=False)

            self.assertIn("source_changed", caught.exception.reasons)
            self.assertIn("coverage_incomplete", caught.exception.reasons)
            self.assertFalse(output.exists())

    def _set_native_attribute(self, path: Path, name: bytes, value: bytes) -> None:
        try:
            if sys.platform.startswith("linux"):
                os.setxattr(path, name, value, follow_symlinks=False)
                return
            library = ctypes.CDLL(None, use_errno=True)
            function = library.setxattr
            function.argtypes = (
                ctypes.c_char_p,
                ctypes.c_char_p,
                ctypes.c_void_p,
                ctypes.c_size_t,
                ctypes.c_uint32,
                ctypes.c_int,
            )
            function.restype = ctypes.c_int
            buffer = ctypes.create_string_buffer(value)
            result = function(
                os.fsencode(path),
                name,
                ctypes.cast(buffer, ctypes.c_void_p),
                len(value),
                0,
                0x0001,
            )
            if result != 0:
                raise OSError(ctypes.get_errno(), "synthetic xattr fixture creation failed")
        except OSError as error:
            if os.environ.get("GITHUB_ACTIONS") == "true":
                self.fail(
                    "GitHub runner could not create the native extended-attribute fixture "
                    f"(errno {error.errno})"
                )
            self.skipTest("the local filesystem does not permit extended-attribute fixtures")


if __name__ == "__main__":
    unittest.main()
