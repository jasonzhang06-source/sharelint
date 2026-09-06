from __future__ import annotations

import gzip
import hashlib
import io
import os
import stat
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from scripts.build_portable import (
    ArchiveMember,
    PortableBuildError,
    PortableTarget,
    _read_native_runtime,
    _read_toc_native_inventory,
    _write_bytes_exclusive,
    _write_tar_gz,
    _write_zip,
    build_portable,
    classify_native_runtime,
    detect_target,
)


class PortableBuildTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="sharelint-portable-tests-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.members = (
            ArchiveMember("sharelint-test/sharelint", b"synthetic executable\n", 0o755),
            ArchiveMember("sharelint-test/LICENSE.txt", b"synthetic license\n"),
        )

    def test_release_target_matrix_is_explicit(self) -> None:
        self.assertEqual(
            detect_target(system="Linux", machine="x86_64", libc_name="glibc").slug,
            "linux-glibc-x86_64",
        )
        self.assertEqual(
            detect_target(system="Windows", machine="AMD64").slug,
            "windows-x86_64",
        )
        self.assertEqual(
            detect_target(system="Darwin", machine="x86_64").slug,
            "macos-x86_64",
        )
        self.assertEqual(
            detect_target(system="Darwin", machine="arm64").slug,
            "macos-arm64",
        )
        for system, machine, libc_name in (
            ("Linux", "aarch64", "glibc"),
            ("Linux", "x86_64", "musl"),
            ("Windows", "ARM64", ""),
        ):
            with (
                self.subTest(system=system, machine=machine),
                self.assertRaises(PortableBuildError),
            ):
                detect_target(system=system, machine=machine, libc_name=libc_name)

    def test_zip_archive_is_deterministic_and_has_fixed_metadata(self) -> None:
        first = self.root / "first.zip"
        second = self.root / "second.zip"
        _write_zip(first, "sharelint-test", self.members)
        _write_zip(second, "sharelint-test", tuple(reversed(self.members)))
        self.assertEqual(first.read_bytes(), second.read_bytes())

        with zipfile.ZipFile(first) as archive:
            self.assertEqual(archive.namelist(), sorted(member.name for member in self.members))
            executable = archive.getinfo("sharelint-test/sharelint")
            self.assertEqual(executable.date_time, (1980, 1, 1, 0, 0, 0))
            self.assertEqual((executable.external_attr >> 16) & 0o777, 0o755)

    def test_tar_archive_is_deterministic_and_preserves_executable_mode(self) -> None:
        first = self.root / "first.tar.gz"
        second = self.root / "second.tar.gz"
        _write_tar_gz(first, "sharelint-test", self.members)
        _write_tar_gz(second, "sharelint-test", tuple(reversed(self.members)))
        self.assertEqual(first.read_bytes(), second.read_bytes())
        with (
            gzip.GzipFile(fileobj=io.BytesIO(first.read_bytes())) as zipped,
            tarfile.open(fileobj=zipped, mode="r:") as archive,
        ):
            self.assertEqual(archive.getnames(), sorted(member.name for member in self.members))
            executable = archive.getmember("sharelint-test/sharelint")
            self.assertEqual(executable.mode, 0o755)
            self.assertEqual(executable.mtime, 0)
            self.assertEqual(executable.uid, 0)
            self.assertEqual(executable.gid, 0)

    def test_writers_refuse_overwrite_symlinks_and_unsafe_members(self) -> None:
        existing = self.root / "existing.zip"
        existing.write_bytes(b"sentinel")
        with self.assertRaises(PortableBuildError):
            _write_zip(existing, "sharelint-test", self.members)
        self.assertEqual(existing.read_bytes(), b"sentinel")

        escaped = self.root / "escaped.zip"
        symlink = self.root / "symlink.zip"
        try:
            symlink.symlink_to(escaped)
        except OSError:
            if os.name == "nt":
                self.skipTest("this Windows environment does not permit symlink creation")
            raise
        with self.assertRaises(PortableBuildError):
            _write_zip(symlink, "sharelint-test", self.members)
        self.assertTrue(symlink.is_symlink())
        self.assertFalse(escaped.exists())

        unsafe = (ArchiveMember("sharelint-test/../escape", b"no"),)
        with self.assertRaises(PortableBuildError):
            _write_tar_gz(self.root / "unsafe.tar.gz", "sharelint-test", unsafe)

    def test_checksum_file_contract_can_be_written_exclusively(self) -> None:
        archive = self.root / "sharelint-v1-test.zip"
        _write_zip(archive, "sharelint-test", self.members)
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        checksum = self.root / f"{archive.name}.sha256"
        _write_bytes_exclusive(checksum, f"{digest}  {archive.name}\n".encode("ascii"))
        self.assertEqual(checksum.read_text(encoding="ascii"), f"{digest}  {archive.name}\n")
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(checksum.stat().st_mode), 0o644)
        with self.assertRaises(PortableBuildError):
            _write_bytes_exclusive(checksum, b"replacement")

    def test_full_builder_rejects_an_unlocked_python_toolchain(self) -> None:
        with (
            mock.patch("scripts.build_portable.platform.python_version", return_value="3.13.14"),
            self.assertRaisesRegex(PortableBuildError, "CPython 3\\.13\\.15"),
        ):
            build_portable(self.root / "output")

    def test_native_runtime_inventory_is_targeted_and_notice_covered(self) -> None:
        cases = {
            "linux-glibc-x86_64": (
                "libcrypto.so.3",
                "libpython3.13.so.1.0",
                "python3.13/lib-dynload/_ssl.cpython-313-x86_64-linux-gnu.so",
            ),
            "windows-x86_64": (
                "_ssl.pyd",
                "libcrypto-3-x64.dll",
                "python313.dll",
            ),
            "macos-x86_64": (
                "libcrypto.3.dylib",
                "libpython3.13.dylib",
                "python3.13/lib-dynload/_ssl.cpython-313-darwin.so",
            ),
            "macos-arm64": (
                "libpython3.13.dylib",
                "python3.13/lib-dynload/_ssl.cpython-313-darwin.so",
            ),
        }
        for target, files in cases.items():
            with self.subTest(target=target):
                inventory = classify_native_runtime(tuple(sorted(files)), target)
                self.assertIn("cpython", inventory.components)
                self.assertEqual(inventory.files, tuple(sorted(files)))

    def test_static_native_components_are_derived_from_locked_platform_rules(self) -> None:
        windows = classify_native_runtime(("_bz2.pyd", "python313.dll"), "windows-x86_64")
        self.assertEqual(windows.components, ("bzip2", "cpython", "mimalloc", "zlib"))
        self.assertEqual(
            {(item.component, item.version) for item in windows.static_components},
            {
                ("bzip2", "1.0.8"),
                ("mimalloc", "2.1.2"),
                ("zlib", "1.3.1"),
                ("zlib", "1.3.2"),
            },
        )

        macos = classify_native_runtime(
            (
                "libpython3.13.dylib",
                "python3.13/lib-dynload/_lzma.cpython-313-darwin.so",
            ),
            "macos-arm64",
        )
        self.assertIn("xz-utils", macos.components)
        self.assertEqual(
            [(item.component, item.version) for item in macos.static_components],
            [("xz-utils", "5.2.3")],
        )

    def test_analysis_and_package_toc_inventories_are_canonical_and_bounded(self) -> None:
        entries = [
            ("python313.dll", "C:/Python/python313.dll", "BINARY"),
            ("_ssl.pyd", "C:/Python/DLLs/_ssl.pyd", "EXTENSION"),
            ("ignored", "C:/build/ignored.pyc", "PYMODULE"),
            ("X utf8=1", None, "OPTION"),
        ]
        analysis_value = tuple(entries if index == 15 else None for index in range(20))
        package_value = tuple(
            list(reversed(entries)) if index == 2 else None for index in range(11)
        )
        analysis = self.root / "Analysis-00.toc"
        package = self.root / "PKG-00.toc"
        analysis.write_text(repr(analysis_value), encoding="utf-8")
        package.write_text(repr(package_value), encoding="utf-8")

        analysis_names, analysis_digest = _read_toc_native_inventory(
            analysis, inventory_index=15, expected_tuple_length=20
        )
        package_names, package_digest = _read_toc_native_inventory(
            package, inventory_index=2, expected_tuple_length=11
        )
        self.assertEqual(analysis_names, ("_ssl.pyd", "python313.dll"))
        self.assertEqual(analysis_names, package_names)
        self.assertEqual(analysis_digest, package_digest)

        duplicate = tuple([entries[0], entries[0]] if index == 15 else None for index in range(20))
        analysis.write_text(repr(duplicate), encoding="utf-8")
        with self.assertRaises(PortableBuildError):
            _read_toc_native_inventory(analysis, inventory_index=15, expected_tuple_length=20)

        missing_native_source = tuple(
            [("python313.dll", None, "BINARY")] if index == 15 else None for index in range(20)
        )
        analysis.write_text(repr(missing_native_source), encoding="utf-8")
        with self.assertRaises(PortableBuildError):
            _read_toc_native_inventory(analysis, inventory_index=15, expected_tuple_length=20)

    def test_final_carchive_native_files_are_hashed_by_identity(self) -> None:
        executable = self.root / "sharelint.exe"
        executable.write_bytes(b"synthetic executable")
        payload = b"synthetic python runtime"

        class Reader:
            def __init__(self, _path: str) -> None:
                self.toc = {
                    "python313.dll": (0, len(payload), len(payload), 0, "b"),
                    "entry": (len(payload), 4, 4, 0, "s"),
                }

            @staticmethod
            def extract(name: str) -> bytes:
                if name != "python313.dll":
                    raise KeyError(name)
                return payload

        with mock.patch(
            "scripts.build_portable.importlib.import_module",
            return_value=SimpleNamespace(CArchiveReader=Reader),
        ):
            inventory = _read_native_runtime(
                executable,
                PortableTarget("windows-x86_64", "sharelint.exe", ".zip"),
            )
        self.assertEqual(inventory.files, ("python313.dll",))
        self.assertEqual(inventory.identities[0].sha256, hashlib.sha256(payload).hexdigest())
        self.assertEqual(inventory.identities[0].size, len(payload))
        self.assertIn("zlib", inventory.components)

    def test_native_runtime_inventory_fails_closed_on_unknown_or_ambiguous_files(self) -> None:
        for files in (
            ("python313.dll", "VCRUNTIME140.dll"),
            ("python313.dll", "python313.dll"),
            ("../python313.dll",),
        ):
            with self.subTest(files=files), self.assertRaises(PortableBuildError):
                classify_native_runtime(files, "windows-x86_64")


if __name__ == "__main__":
    unittest.main()
