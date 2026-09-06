from __future__ import annotations

import hashlib
import io
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from scripts.check_pypi_release import (
    PyPIRecoveryError,
    local_distributions,
    publication_required,
    reconcile_publication,
)
from scripts.normalize_sdist import normalize_sdist


class PyPIRecoveryTests(unittest.TestCase):
    version = "9.8.7"

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="sharelint-pypi-recovery-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        metadata = f"Metadata-Version: 2.4\nName: sharelint\nVersion: {self.version}\n\n"
        wheel = self.directory / f"sharelint-{self.version}-py3-none-any.whl"
        with zipfile.ZipFile(wheel, "w") as archive:
            archive.writestr(f"sharelint-{self.version}.dist-info/METADATA", metadata)
        sdist = self.directory / f"sharelint-{self.version}.tar.gz"
        root = f"sharelint-{self.version}"
        with tarfile.open(sdist, "w:gz", format=tarfile.PAX_FORMAT) as archive:
            directory = tarfile.TarInfo(root)
            directory.type = tarfile.DIRTYPE
            archive.addfile(directory)
            info = tarfile.TarInfo(f"{root}/PKG-INFO")
            payload = metadata.encode()
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
        normalize_sdist(sdist, project="sharelint", version=self.version)

    def _local(self) -> dict[str, str]:
        return local_distributions(self.directory, project="sharelint", version=self.version)

    def _payload(self, distributions: dict[str, str]) -> dict[str, object]:
        return {
            "info": {"version": self.version},
            "urls": [
                {"filename": name, "digests": {"sha256": digest}}
                for name, digest in distributions.items()
            ],
        }

    def test_absent_version_requires_publication(self) -> None:
        local = self._local()
        self.assertTrue(publication_required(local, None, version=self.version))

    def test_identical_existing_release_is_a_safe_retry(self) -> None:
        local = self._local()
        self.assertFalse(publication_required(local, self._payload(local), version=self.version))

    def test_partial_extra_or_changed_existing_release_fails_closed(self) -> None:
        local = self._local()
        cases = (
            dict(tuple(local.items())[:1]),
            {**local, "unexpected.whl": hashlib.sha256(b"unexpected").hexdigest()},
            {**local, next(iter(local)): hashlib.sha256(b"changed").hexdigest()},
        )
        for remote in cases:
            with self.subTest(remote=remote), self.assertRaises(PyPIRecoveryError):
                publication_required(local, self._payload(remote), version=self.version)

    def test_local_distribution_inventory_is_exact(self) -> None:
        (self.directory / "extra.txt").write_text("extra\n", encoding="utf-8")
        with self.assertRaises(PyPIRecoveryError):
            self._local()

    def test_local_distribution_metadata_is_bound_to_project_and_version(self) -> None:
        wheel = self.directory / f"sharelint-{self.version}-py3-none-any.whl"
        with zipfile.ZipFile(wheel, "w") as archive:
            archive.writestr(
                f"sharelint-{self.version}.dist-info/METADATA",
                f"Metadata-Version: 2.4\nName: another-project\nVersion: {self.version}\n\n",
            )
        with self.assertRaisesRegex(PyPIRecoveryError, "metadata"):
            self._local()

    def test_reconciliation_only_publishes_after_all_queries_are_404(self) -> None:
        local = self._local()
        with (
            patch("scripts.check_pypi_release._fetch_release_once", return_value=None) as fetch,
            patch("scripts.check_pypi_release.time.sleep"),
        ):
            self.assertEqual(
                reconcile_publication(local, project="sharelint", version=self.version, attempts=3),
                "publish",
            )
            self.assertEqual(fetch.call_count, 3)

    def test_reconciliation_reuses_eventual_exact_result_and_never_downgrades_mismatch(
        self,
    ) -> None:
        local = self._local()
        exact = self._payload(local)
        changed = self._payload(
            {**local, next(iter(local)): hashlib.sha256(b"changed").hexdigest()}
        )
        with (
            patch(
                "scripts.check_pypi_release._fetch_release_once",
                side_effect=[None, exact],
            ),
            patch("scripts.check_pypi_release.time.sleep"),
        ):
            self.assertEqual(
                reconcile_publication(local, project="sharelint", version=self.version, attempts=2),
                "reuse",
            )
        with (
            patch(
                "scripts.check_pypi_release._fetch_release_once",
                side_effect=[changed, None],
            ),
            patch("scripts.check_pypi_release.time.sleep"),
            self.assertRaises(PyPIRecoveryError),
        ):
            reconcile_publication(local, project="sharelint", version=self.version, attempts=2)


if __name__ == "__main__":
    unittest.main()
