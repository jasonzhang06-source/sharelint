from __future__ import annotations

import gzip
import hashlib
import io
import tarfile
import tempfile
import unittest
from pathlib import Path

from scripts.normalize_sdist import (
    SdistNormalizationError,
    normalize_sdist,
)


class SdistReproducibilityTests(unittest.TestCase):
    project = "sharelint"
    version = "1.2.3"
    root_name = "sharelint-1.2.3"

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="sharelint-sdist-tests-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def _write_sdist(
        self,
        directory: Path,
        *,
        mtime: int,
        reverse: bool = False,
        unsafe: str | None = None,
    ) -> Path:
        directory.mkdir()
        path = directory / f"{self.root_name}.tar.gz"
        records = [
            (self.root_name, None),
            (f"{self.root_name}/README.md", b"synthetic readme\n"),
            (f"{self.root_name}/src", None),
            (f"{self.root_name}/src/module.py", b"value = 1\n"),
        ]
        if reverse:
            records.reverse()
        with tarfile.open(path, "w:gz", format=tarfile.PAX_FORMAT) as archive:
            for name, data in records:
                info = tarfile.TarInfo(name)
                info.mtime = mtime
                info.uid = mtime
                info.gid = mtime
                info.uname = "builder"
                info.gname = "builder"
                if data is None:
                    info.type = tarfile.DIRTYPE
                    info.mode = 0o775
                    archive.addfile(info)
                else:
                    info.mode = 0o664
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))
            if unsafe is not None:
                info = tarfile.TarInfo(unsafe)
                info.type = tarfile.SYMTYPE
                info.linkname = "outside"
                archive.addfile(info)
        return path

    def test_different_source_metadata_normalizes_to_identical_bytes(self) -> None:
        first = self._write_sdist(self.root / "first", mtime=1)
        second = self._write_sdist(self.root / "second", mtime=999_999, reverse=True)
        self.assertNotEqual(
            hashlib.sha256(first.read_bytes()).digest(),
            hashlib.sha256(second.read_bytes()).digest(),
        )

        normalize_sdist(first, project=self.project, version=self.version)
        normalize_sdist(second, project=self.project, version=self.version)
        self.assertEqual(first.read_bytes(), second.read_bytes())
        normalize_sdist(first, project=self.project, version=self.version, check=True)

        self.assertTrue(first.read_bytes().startswith(b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff"))
        with tarfile.open(first, "r:gz") as archive:
            members = archive.getmembers()
            self.assertEqual(
                [member.name for member in members], sorted(member.name for member in members)
            )
            for member in members:
                self.assertEqual(member.mtime, 0)
                self.assertEqual(member.uid, 0)
                self.assertEqual(member.gid, 0)
                self.assertFalse(member.uname)
                self.assertFalse(member.gname)
                self.assertFalse(member.pax_headers)

    def test_check_rejects_valid_but_noncanonical_sdist(self) -> None:
        path = self._write_sdist(self.root / "check", mtime=42)
        with self.assertRaisesRegex(SdistNormalizationError, "not canonical"):
            normalize_sdist(path, project=self.project, version=self.version, check=True)

    def test_wrong_filename_and_unsafe_member_fail_closed(self) -> None:
        path = self._write_sdist(self.root / "unsafe", mtime=0, unsafe=f"{self.root_name}/link")
        with self.assertRaises(SdistNormalizationError):
            normalize_sdist(path, project=self.project, version=self.version)

        wrong = self.root / "wrong.tar.gz"
        wrong.write_bytes(gzip.compress(b"not a tar"))
        with self.assertRaisesRegex(SdistNormalizationError, "filename"):
            normalize_sdist(wrong, project=self.project, version=self.version)


if __name__ == "__main__":
    unittest.main()
