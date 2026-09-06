from __future__ import annotations

import io
import os
import subprocess
import sys
from unittest import mock

import tests.bootstrap  # noqa: F401
from sharelint.cli import main
from sharelint.packing import pack
from tests.cli_harness import REPO_ROOT, CliTestCase


class CliFailureTests(CliTestCase):
    def test_keyboard_interrupt_returns_130_without_a_traceback(self) -> None:
        error = io.StringIO()
        with (
            mock.patch("sharelint.cli._demo_command", side_effect=KeyboardInterrupt),
            mock.patch("sharelint.cli.sys.stderr", error),
        ):
            self.assertEqual(main(["demo"]), 130)
        self.assertIn("interrupted", error.getvalue())
        self.assertNotIn("Traceback", error.getvalue())

    def test_closed_stdout_is_an_io_failure_even_for_buffered_output(self) -> None:
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(REPO_ROOT / "src")
        for command in (
            ("config", "show"),
            ("--version",),
            ("--help",),
            ("demo", "--format", "json"),
        ):
            with self.subTest(command=command):
                process = subprocess.Popen(
                    [sys.executable, "-m", "sharelint", *command],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=environment,
                )
                self.assertIsNotNone(process.stdout)
                self.assertIsNotNone(process.stderr)
                process.stdout.close()
                try:
                    process.wait(timeout=15)
                    error = process.stderr.read().decode("utf-8", errors="replace")
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.wait(timeout=5)
                    process.stderr.close()
                self.assertEqual(process.returncode, 2, error)
                self.assertNotIn("Traceback", error)
                self.assertNotIn("Exception ignored", error)
                self.assertTrue(
                    any(
                        message in error
                        for message in (
                            "output pipe closed",
                            "output could not be completed",
                            "operating system operation failed",
                        )
                    ),
                    error,
                )

    def test_broken_in_memory_streams_do_not_escape_exception_handler(self) -> None:
        output = io.StringIO()
        error = io.StringIO()
        with (
            mock.patch("sharelint.cli._main", side_effect=BrokenPipeError),
            mock.patch("sharelint.cli.sys.stdout", output),
            mock.patch("sharelint.cli.sys.stderr", error),
        ):
            self.assertEqual(main(["demo"]), 2)
        self.assertIn("not fully delivered", error.getvalue())

    def test_cancel_during_report_publication_rolls_back_only_owned_outputs(self) -> None:
        source = self.root / "public.txt"
        source.write_text("ordinary synthetic public text\n", encoding="utf-8")
        bundle = self.root / "bundle.zip"
        receipt = self.root / "receipt.json"
        report = self.root / "report.json"
        with (
            mock.patch("sharelint.packing._write_document", side_effect=KeyboardInterrupt),
            self.assertRaises(KeyboardInterrupt),
        ):
            pack(source, bundle, receipt=receipt, report_output=report)
        self.assertFalse(bundle.exists())
        self.assertFalse(receipt.exists())
        self.assertFalse(report.exists())
        self.assertEqual(source.read_text(encoding="utf-8"), "ordinary synthetic public text\n")

    def test_flush_io_failure_has_a_stable_exit_and_private_diagnostic(self) -> None:
        class FailedFlush(io.StringIO):
            def flush(self) -> None:
                raise OSError("PRIVATE_PLATFORM_ERROR")

        error = io.StringIO()
        with (
            mock.patch("sharelint.cli._main", return_value=0),
            mock.patch("sharelint.cli.sys.stdout", FailedFlush()),
            mock.patch("sharelint.cli.sys.stderr", error),
        ):
            self.assertEqual(main([]), 2)
        self.assertNotIn("PRIVATE_PLATFORM_ERROR", error.getvalue())
        self.assertIn("output could not be completed", error.getvalue())
