from __future__ import annotations

import hashlib
import json
import stat
import tempfile
import unittest
import zipfile
from dataclasses import asdict
from pathlib import Path
from unittest.mock import patch

from scripts.build_portable import (
    LICENSE_CATALOG,
    ArchiveMember,
    NativeFileIdentity,
    NativeRuntimeInventory,
    PortableTarget,
    _render_portable_readme,
    _write_bytes_exclusive,
    _write_tar_gz,
    _write_zip,
    classify_native_runtime,
)
from scripts.verify_release_assets import (
    AssetVerificationError,
    _build_lock_sha256,
    verify_archive,
    verify_directory,
)


class ReleaseAssetTests(unittest.TestCase):
    version = "9.8.7"

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="sharelint-release-assets-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    @staticmethod
    def _native_inventory(target: str) -> NativeRuntimeInventory:
        filename = {
            "linux-glibc-x86_64": "libpython3.13.so.1.0",
            "windows-x86_64": "python313.dll",
            "macos-x86_64": "libpython3.13.dylib",
            "macos-arm64": "libpython3.13.dylib",
        }[target]
        classified = classify_native_runtime((filename,), target)
        identity = NativeFileIdentity(
            name=filename,
            sha256=hashlib.sha256(b"synthetic native runtime").hexdigest(),
            size=len(b"synthetic native runtime"),
        )
        return NativeRuntimeInventory(
            files=(filename,),
            components=classified.components,
            identities=(identity,),
            static_components=classified.static_components,
        )

    def _members(self, target: str, executable: str, payload: bytes) -> tuple[ArchiveMember, ...]:
        root = f"sharelint-v{self.version}-{target}"
        components = {
            "altgraph": "0.17.5",
            "build": "1.5.0",
            "packaging": "26.3",
            "pip": "26.2.1",
            "pyinstaller": "6.22.2",
            "pyinstaller-hooks-contrib": "2026.6",
            "pyproject-hooks": "1.2.0",
            "setuptools": "84.0.0",
            "sharelint": self.version,
        }
        if target.startswith("macos-"):
            components["macholib"] = "1.16.4"
        if target.startswith("windows-"):
            components.update(
                {"colorama": "0.4.6", "pefile": "2024.8.26", "pywin32-ctypes": "0.2.3"}
            )
        native_runtime = self._native_inventory(target)
        notices = (
            Path(__file__).resolve().parents[1] / "scripts" / "THIRD-PARTY-NOTICES.txt"
        ).read_bytes()
        build_info = {
            "build_components": components,
            "build_lock_sha256": _build_lock_sha256(),
            "executable_sha256": hashlib.sha256(payload).hexdigest(),
            "format_version": 2,
            "license_catalog_sha256": hashlib.sha256(LICENSE_CATALOG.read_bytes()).hexdigest(),
            "native_runtime": {
                "analysis_inventory_sha256": "a" * 64,
                "components": list(native_runtime.components),
                "files": [asdict(item) for item in native_runtime.identities],
                "package_inventory_sha256": "a" * 64,
                "static_components": [asdict(item) for item in native_runtime.static_components],
            },
            "python": {"implementation": "CPython", "version": "3.13.15"},
            "sharelint_version": self.version,
            "target": target,
            "third_party_notices_sha256": hashlib.sha256(notices).hexdigest(),
        }
        return (
            ArchiveMember(f"{root}/{executable}", payload, 0o755),
            ArchiveMember(
                f"{root}/BUILD-INFO.json",
                (json.dumps(build_info, sort_keys=True) + "\n").encode(),
            ),
            ArchiveMember(
                f"{root}/LICENSE.txt",
                (Path(__file__).resolve().parents[1] / "LICENSE").read_bytes(),
            ),
            ArchiveMember(
                f"{root}/PYTHON-LICENSE.txt",
                b"PYTHON SOFTWARE FOUNDATION LICENSE VERSION 2\n",
            ),
            ArchiveMember(
                f"{root}/PYINSTALLER-LICENSE.txt",
                b"GNU GPL with Bootloader Exception\n",
            ),
            ArchiveMember(f"{root}/THIRD-PARTY-NOTICES.txt", notices),
            ArchiveMember(
                f"{root}/README.txt",
                _render_portable_readme(
                    Path(__file__).resolve().parents[1] / "scripts" / "PORTABLE_README.txt",
                    version=self.version,
                    target=PortableTarget(
                        target,
                        executable,
                        ".zip" if executable.endswith(".exe") else ".tar.gz",
                    ),
                ),
            ),
        )

    def _write_fixture(self, target: str) -> tuple[Path, Path, Path]:
        suffix = ".zip" if target == "windows-x86_64" else ".tar.gz"
        executable_name = "sharelint.exe" if suffix == ".zip" else "sharelint"
        archive = self.root / f"sharelint-v{self.version}-{target}{suffix}"
        payload = b"synthetic frozen executable\n"
        members = self._members(target, executable_name, payload)
        root_name = f"sharelint-v{self.version}-{target}"
        if suffix == ".zip":
            _write_zip(archive, root_name, members)
        else:
            _write_tar_gz(archive, root_name, members)
        checksum = self.root / f"{archive.name}.sha256"
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        _write_bytes_exclusive(checksum, f"{digest}  {archive.name}\n".encode("ascii"))
        loose = self.root / executable_name
        loose.write_bytes(payload)
        return archive, checksum, loose

    def test_valid_zip_and_tar_bind_the_smoke_tested_executable(self) -> None:
        for target in ("windows-x86_64", "linux-glibc-x86_64"):
            with self.subTest(target=target):
                subdirectory = self.root / target
                subdirectory.mkdir()
                original_root = self.root
                self.root = subdirectory
                try:
                    archive, checksum, loose = self._write_fixture(target)
                    with patch(
                        "scripts.verify_release_assets._read_native_runtime",
                        return_value=self._native_inventory(target),
                    ):
                        verified = verify_archive(
                            archive,
                            checksum,
                            target=target,
                            version=self.version,
                            loose_executable=loose,
                        )
                        self.assertEqual(
                            verified.executable_sha256,
                            hashlib.sha256(loose.read_bytes()).hexdigest(),
                        )
                        self.assertEqual(
                            len(
                                verify_directory(
                                    self.root,
                                    version=self.version,
                                    target=target,
                                    all_targets=False,
                                    loose_executable=loose,
                                )
                            ),
                            1,
                        )
                finally:
                    self.root = original_root

    def test_zip_comment_and_symlink_member_are_rejected(self) -> None:
        comment_dir = self.root / "comment"
        comment_dir.mkdir()
        self.root = comment_dir
        archive, checksum, _ = self._write_fixture("windows-x86_64")
        with zipfile.ZipFile(archive, "a") as bundle:
            bundle.comment = b"unexpected"
        checksum.write_text(
            f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}\n",
            encoding="ascii",
        )
        with self.assertRaises(AssetVerificationError):
            verify_archive(
                archive,
                checksum,
                target="windows-x86_64",
                version=self.version,
            )

        symlink_dir = self.root.parent / "symlink-member"
        symlink_dir.mkdir()
        self.root = symlink_dir
        archive, checksum, _ = self._write_fixture("windows-x86_64")
        root_name = f"sharelint-v{self.version}-windows-x86_64"
        replacement = self.root / "replacement.zip"
        members = self._members("windows-x86_64", "sharelint.exe", b"payload")
        with zipfile.ZipFile(replacement, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
            for member in members:
                info = zipfile.ZipInfo(member.name, (1980, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.compress_type = zipfile.ZIP_DEFLATED
                file_type = (
                    stat.S_IFLNK if member.name == f"{root_name}/sharelint.exe" else stat.S_IFREG
                )
                info.external_attr = (file_type | member.mode) << 16
                bundle.writestr(info, member.data)
        archive.unlink()
        replacement.rename(archive)
        checksum.write_text(
            f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}\n",
            encoding="ascii",
        )
        with self.assertRaises(AssetVerificationError):
            verify_archive(
                archive,
                checksum,
                target="windows-x86_64",
                version=self.version,
            )

    def test_hidden_trailing_bytes_and_wrong_project_license_are_rejected(self) -> None:
        for target in ("windows-x86_64", "linux-glibc-x86_64"):
            with self.subTest(target=target):
                directory = self.root / target
                directory.mkdir()
                original_root = self.root
                self.root = directory
                try:
                    archive, checksum, _ = self._write_fixture(target)
                    with archive.open("ab") as stream:
                        stream.write(b"hidden trailing payload")
                    checksum.write_text(
                        f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}\n",
                        encoding="ascii",
                    )
                    with self.assertRaises(AssetVerificationError):
                        verify_archive(archive, checksum, target=target, version=self.version)
                finally:
                    self.root = original_root

        target = "linux-glibc-x86_64"
        directory = self.root / "license"
        directory.mkdir()
        root_name = f"sharelint-v{self.version}-{target}"
        archive = directory / f"{root_name}.tar.gz"
        members = tuple(
            ArchiveMember(member.name, b"fake license\n", member.mode)
            if member.name.endswith("/LICENSE.txt")
            else member
            for member in self._members(target, "sharelint", b"payload")
        )
        _write_tar_gz(archive, root_name, members)
        checksum = directory / f"{archive.name}.sha256"
        checksum.write_text(
            f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}\n",
            encoding="ascii",
        )
        with self.assertRaises(AssetVerificationError):
            verify_archive(archive, checksum, target=target, version=self.version)

    def test_wrong_checksum_and_loose_executable_are_rejected(self) -> None:
        archive, checksum, loose = self._write_fixture("linux-glibc-x86_64")
        loose.write_bytes(b"different executable")
        with self.assertRaises(AssetVerificationError):
            verify_archive(
                archive,
                checksum,
                target="linux-glibc-x86_64",
                version=self.version,
                loose_executable=loose,
            )
        checksum.write_text(f"{'0' * 64}  {archive.name}\n", encoding="ascii")
        with self.assertRaises(AssetVerificationError):
            verify_archive(
                archive,
                checksum,
                target="linux-glibc-x86_64",
                version=self.version,
            )

    def test_directory_rejects_unexpected_non_release_files(self) -> None:
        _, _, loose = self._write_fixture("linux-glibc-x86_64")
        (self.root / "unexpected.txt").write_text("unexpected\n", encoding="utf-8")
        with self.assertRaises(AssetVerificationError):
            verify_directory(
                self.root,
                version=self.version,
                target="linux-glibc-x86_64",
                all_targets=False,
                loose_executable=loose,
            )


if __name__ == "__main__":
    unittest.main()
