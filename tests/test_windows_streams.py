from __future__ import annotations

import ctypes
import json
import os
import tempfile
import unittest
from pathlib import Path

import tests.bootstrap  # noqa: F401
from sharelint import windows_streams
from sharelint.context import ScanContext
from sharelint.models import ScanLimits, Severity, SurfaceStatus
from sharelint.packing import PackBlocked, pack
from sharelint.scanner import scan
from sharelint.windows_streams import (
    WindowsStreamStatus,
    inspect_windows_streams,
    record_windows_stream_coverage,
)

_INVALID_HANDLE = ctypes.c_void_p(-1).value
assert _INVALID_HANDLE is not None


class FakeStreamApi:
    def __init__(
        self,
        names: list[str] | None = None,
        *,
        first_error: int = 38,
        terminal_error: int = 38,
        close_succeeds: bool = True,
    ) -> None:
        self.names = names or []
        self.first_error = first_error
        self.terminal_error = terminal_error
        self.close_succeeds = close_succeeds
        self.index = 0
        self.current_error = first_error
        self.closed_handles: list[int] = []

    def find_first(self, path: str, data: windows_streams._Win32FindStreamData) -> int:
        del path
        if not self.names:
            self.current_error = self.first_error
            return _INVALID_HANDLE
        data.stream_name = self.names[0]
        self.index = 1
        return 71

    def find_next(self, handle: int, data: windows_streams._Win32FindStreamData) -> bool:
        self.assert_handle(handle)
        if self.index < len(self.names):
            data.stream_name = self.names[self.index]
            self.index += 1
            return True
        self.current_error = self.terminal_error
        return False

    def last_error(self) -> int:
        return self.current_error

    def close(self, handle: int) -> bool:
        self.assert_handle(handle)
        self.closed_handles.append(handle)
        return self.close_succeeds

    @staticmethod
    def assert_handle(handle: int) -> None:
        if handle != 71:
            raise AssertionError("unexpected synthetic handle")


class WindowsStreamEnumerationTests(unittest.TestCase):
    def test_non_windows_platform_is_not_applicable_without_loading_win32(self) -> None:
        original_name = windows_streams.os.name
        try:
            windows_streams.os.name = "posix"
            status = inspect_windows_streams("synthetic.txt", is_directory=False)
        finally:
            windows_streams.os.name = original_name

        self.assertIs(status, WindowsStreamStatus.NOT_APPLICABLE)

    def test_default_stream_only_is_scanned_and_handle_is_closed(self) -> None:
        api = FakeStreamApi(["::$DATA"])

        status = inspect_windows_streams("synthetic.txt", is_directory=False, _api=api)

        self.assertIs(status, WindowsStreamStatus.SCANNED)
        self.assertEqual(api.closed_handles, [71])

    def test_named_stream_is_detected_without_returning_its_name(self) -> None:
        private_name = ":FICTITIOUS_PRIVATE_STREAM:$DATA"
        api = FakeStreamApi(["::$DATA", private_name])

        status = inspect_windows_streams("synthetic.txt", is_directory=False, _api=api)

        self.assertIs(status, WindowsStreamStatus.NAMED_STREAM_PRESENT)
        self.assertNotIn(private_name, status.value)
        self.assertEqual(api.closed_handles, [71])

    def test_no_stream_and_unsupported_filesystem_have_distinct_results(self) -> None:
        empty_directory = inspect_windows_streams(
            "synthetic-directory",
            is_directory=True,
            _api=FakeStreamApi(first_error=38),
        )
        missing_default_stream = inspect_windows_streams(
            "synthetic.txt", is_directory=False, _api=FakeStreamApi(first_error=38)
        )
        unsupported = inspect_windows_streams(
            "synthetic.txt",
            is_directory=False,
            _api=FakeStreamApi(first_error=87),
        )

        self.assertIs(empty_directory, WindowsStreamStatus.SCANNED)
        self.assertIs(missing_default_stream, WindowsStreamStatus.ENUMERATION_ERROR)
        self.assertIs(unsupported, WindowsStreamStatus.NOT_APPLICABLE)

    def test_enumeration_or_close_failure_is_fail_closed(self) -> None:
        enumeration_failure = inspect_windows_streams(
            "synthetic.txt",
            is_directory=False,
            _api=FakeStreamApi(["::$DATA"], terminal_error=5),
        )
        close_failure = inspect_windows_streams(
            "synthetic.txt",
            is_directory=False,
            _api=FakeStreamApi(["::$DATA"], close_succeeds=False),
        )

        self.assertIs(enumeration_failure, WindowsStreamStatus.ENUMERATION_ERROR)
        self.assertIs(close_failure, WindowsStreamStatus.ENUMERATION_ERROR)

    def test_stream_record_enumeration_is_bounded(self) -> None:
        api = FakeStreamApi(["::$DATA"] * (windows_streams._MAX_STREAM_RECORDS + 1))

        status = inspect_windows_streams("synthetic.txt", is_directory=False, _api=api)

        self.assertIs(status, WindowsStreamStatus.ENUMERATION_ERROR)
        self.assertEqual(api.closed_handles, [71])

    def test_named_stream_records_high_finding_and_skipped_surface_privately(self) -> None:
        private_name = ":FICTITIOUS_CLIENT_PRIVATE_STREAM:$DATA"
        private_value = "FICTITIOUS_ADS_CONTENT_MUST_NOT_ESCAPE"
        context = ScanContext(ScanLimits())

        status = record_windows_stream_coverage(
            "synthetic.txt",
            ("synthetic.txt",),
            context,
            is_directory=False,
            _api=FakeStreamApi(["::$DATA", private_name]),
        )

        self.assertIs(status, WindowsStreamStatus.NAMED_STREAM_PRESENT)
        self.assertEqual(len(context.findings), 1)
        self.assertEqual(context.findings[0].rule_id, "SL.FILESYSTEM.ALTERNATE_DATA_STREAM")
        self.assertIs(context.findings[0].severity, Severity.HIGH)
        self.assertEqual(len(context.surfaces), 1)
        self.assertIs(context.surfaces[0].status, SurfaceStatus.SKIPPED)
        serialized = json.dumps(
            {
                "findings": [item.to_dict() for item in context.findings],
                "surfaces": [item.to_dict() for item in context.surfaces],
                "errors": [item.to_dict() for item in context.errors],
            }
        )
        self.assertNotIn(private_name, serialized)
        self.assertNotIn(private_value, serialized)

    def test_enumeration_error_records_only_fixed_coverage_messages(self) -> None:
        context = ScanContext(ScanLimits())

        status = record_windows_stream_coverage(
            "synthetic.txt",
            ("synthetic.txt",),
            context,
            is_directory=False,
            _api=FakeStreamApi(["::$DATA"], terminal_error=1234),
        )

        self.assertIs(status, WindowsStreamStatus.ENUMERATION_ERROR)
        self.assertEqual(
            [error.message for error in context.errors],
            ["Windows alternate data streams could not be enumerated"],
        )
        self.assertEqual(
            context.surfaces[0].note, "Windows alternate data stream enumeration failed"
        )
        self.assertIs(context.surfaces[0].status, SurfaceStatus.SKIPPED)

    def test_clean_enumeration_records_scanned_surface(self) -> None:
        context = ScanContext(ScanLimits())

        status = record_windows_stream_coverage(
            "synthetic.txt",
            ("synthetic.txt",),
            context,
            is_directory=False,
            _api=FakeStreamApi(["::$DATA"]),
        )

        self.assertIs(status, WindowsStreamStatus.SCANNED)
        self.assertEqual(context.findings, [])
        self.assertEqual(context.errors, [])
        self.assertIs(context.surfaces[0].status, SurfaceStatus.SCANNED)

    @unittest.skipUnless(os.name == "nt", "native alternate data streams require Windows")
    def test_native_windows_file_and_directory_ads_are_detected_without_disclosure(self) -> None:
        stream_name = "FICTITIOUS_PRIVATE_STREAM_NAME"
        stream_value = b"FICTITIOUS_PRIVATE_STREAM_CONTENT"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixtures = [root / "ordinary.txt", root / "ordinary-directory"]
            fixtures[0].write_text("ordinary synthetic text", encoding="utf-8")
            fixtures[1].mkdir()

            for fixture in fixtures:
                with self.subTest(kind="directory" if fixture.is_dir() else "file"):
                    try:
                        with open(f"{fixture}:{stream_name}", "wb") as stream:
                            stream.write(stream_value)
                    except OSError as exc:
                        if os.environ.get("GITHUB_ACTIONS") == "true":
                            self.fail(
                                f"GitHub Windows runner could not create ADS fixture: {exc!r}"
                            )
                        self.skipTest("the local Windows filesystem does not support ADS fixtures")

                    self.assertIs(
                        inspect_windows_streams(fixture, is_directory=fixture.is_dir()),
                        WindowsStreamStatus.NAMED_STREAM_PRESENT,
                    )
                    context = ScanContext(ScanLimits())
                    record_windows_stream_coverage(
                        fixture,
                        ("synthetic-object",),
                        context,
                        is_directory=fixture.is_dir(),
                    )
                    serialized = json.dumps(
                        {
                            "findings": [item.to_dict() for item in context.findings],
                            "surfaces": [item.to_dict() for item in context.surfaces],
                            "errors": [item.to_dict() for item in context.errors],
                        }
                    )
                    self.assertNotIn(stream_name, serialized)
                    self.assertNotIn(stream_value.decode("ascii"), serialized)

            report = scan(root)
            serialized_report = json.dumps(report.to_dict(), sort_keys=True)
            ads_findings = [
                finding
                for finding in report.findings
                if finding.rule_id == "SL.FILESYSTEM.ALTERNATE_DATA_STREAM"
            ]
            self.assertEqual(len(ads_findings), 2)
            self.assertTrue(report.has_coverage_gaps)
            self.assertEqual(report.summary()["verdict"], "incomplete")
            self.assertNotIn(stream_name, serialized_report)
            self.assertNotIn(stream_value.decode("ascii"), serialized_report)

            output = root.parent / "must-not-exist.zip"
            with self.assertRaises(PackBlocked):
                pack(root, output, write_receipt=False)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
