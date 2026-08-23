from __future__ import annotations

import unittest
from pathlib import Path

from tests.cli_harness import CliTestCase
from tests.contract import assert_scan_contract
from tests.helpers import sha256_file, write_traversal_zip, write_zip_bomb


def _snapshot(root: Path) -> set[str]:
    return {str(path.relative_to(root)) for path in root.rglob("*")}


class ArchiveSafetyTests(CliTestCase):
    def test_zip_path_traversal_is_reported_without_writing_outside_archive(self) -> None:
        sentinel = self.root / "FICTITIOUS_ESCAPE.txt"
        sentinel.write_text("sentinel must remain byte-identical\n", encoding="utf-8")
        archive = write_traversal_zip(self.root / "inputs" / "traversal.zip")
        sentinel_sha256 = sha256_file(sentinel)
        archive_sha256 = sha256_file(archive)
        before = _snapshot(self.root)

        result = self.run_cli("scan", archive, "--format", "json")

        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(
            _snapshot(self.root),
            before,
            "scan must be read-only, including for hostile member names",
        )
        self.assertEqual(sha256_file(sentinel), sentinel_sha256)
        self.assertEqual(sha256_file(archive), archive_sha256)
        scan_findings = assert_scan_contract(result.json())
        traversal = [
            finding
            for finding in scan_findings
            if finding["rule_id"] == "SL.ARCHIVE.PATH_TRAVERSAL"
        ]
        self.assertTrue(traversal, f"no path-traversal finding in {scan_findings!r}")
        self.assertTrue(all(finding["severity"] == "critical" for finding in traversal))
        self.assertTrue(all(".." not in finding["source_chain"][-1] for finding in traversal))
        self.assert_omits("../FICTITIOUS_ESCAPE.txt", result.stdout, result.stderr)
        self.assert_omits(
            "safe/../../FICTITIOUS_NESTED_ESCAPE.txt",
            result.stdout,
            result.stderr,
        )

    def test_high_compression_ratio_is_bounded_and_reported_as_blocker(self) -> None:
        archive = write_zip_bomb(self.root / "high-ratio.zip")
        before = _snapshot(self.root)

        result = self.run_cli("scan", archive, "--format", "json", timeout=12)

        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(_snapshot(self.root), before)
        scan_findings = assert_scan_contract(result.json())
        suspicious = [
            finding
            for finding in scan_findings
            if finding["rule_id"] == "SL.ARCHIVE.LIMIT_EXCEEDED"
        ]
        self.assertTrue(suspicious, f"no expansion-limit finding in {scan_findings!r}")
        self.assertTrue(all(finding["severity"] == "high" for finding in suspicious))
        self.assertTrue(
            any(
                "FICTITIOUS_HIGH_RATIO.bin" in "\n".join(item["source_chain"])
                for item in suspicious
            )
        )


if __name__ == "__main__":
    unittest.main()
