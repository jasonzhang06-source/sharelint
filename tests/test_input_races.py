from __future__ import annotations

import os
import unittest
from pathlib import Path
from unittest import mock

import tests.bootstrap  # noqa: F401
from sharelint.input_io import DocumentInputError, read_document
from sharelint.packing import PackError, _read_regular
from sharelint.scanner import scan
from tests.cli_harness import CliTestCase


class InputRaceTests(CliTestCase):
    @unittest.skipUnless(hasattr(os, "mkfifo") and hasattr(os, "O_NONBLOCK"), "POSIX FIFO race")
    def test_regular_file_replaced_by_fifo_cannot_block_any_reader(self) -> None:
        real_open = os.open
        for reader in ("scan", "pack", "document"):
            with self.subTest(reader=reader):
                target = self.root / f"{reader}.txt"
                target.write_bytes(b"synthetic ordinary text")
                fifo = self.root / f"{reader}.fifo"
                os.mkfifo(fifo)

                def replace_before_open(
                    path: Path,
                    flags: int,
                    *args: object,
                    task_target: Path = target,
                    task_fifo: Path = fifo,
                    **kwargs: object,
                ) -> int:
                    if Path(path) == task_target:
                        # Fail before opening if the protection regresses: tests cannot hang.
                        self.assertTrue(flags & os.O_NONBLOCK)
                        os.replace(task_fifo, task_target)
                    return real_open(path, flags, *args, **kwargs)

                with mock.patch("os.open", side_effect=replace_before_open):
                    if reader == "scan":
                        report = scan(target)
                        self.assertTrue(report.has_coverage_gaps)
                        self.assertIn("SL.SCAN.READ_ERROR", {item.code for item in report.errors})
                    elif reader == "pack":
                        with self.assertRaises(PackError):
                            _read_regular(target, 1024)
                    else:
                        with self.assertRaises(DocumentInputError):
                            read_document(target, 1024)

    def test_pack_rechecks_the_path_identity_after_reading(self) -> None:
        target = self.root / "input.txt"
        target.write_bytes(b"ordinary synthetic text")
        replacement = self.root / "replacement.txt"
        replacement.write_bytes(b"different synthetic text")
        from sharelint import packing

        real_read = packing._read_bounded

        def replace_after_read(stream: object, limit: int) -> bytes:
            data = real_read(stream, limit)
            # Windows prevents replacing an open file on some filesystems.
            try:
                os.replace(replacement, target)
            except PermissionError:
                self.skipTest("filesystem disallows replacing an open source")
            return data

        with (
            mock.patch("sharelint.packing._read_bounded", side_effect=replace_after_read),
            self.assertRaises(PackError),
        ):
            _read_regular(target, 1024)
