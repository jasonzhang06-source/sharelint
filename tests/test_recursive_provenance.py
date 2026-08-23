from __future__ import annotations

import unittest

from tests.cli_harness import CliTestCase
from tests.contract import assert_scan_contract, chain_contains_in_order
from tests.helpers import FICTIONAL_NAME, FICTIONAL_SECRET, write_docx, write_zip


class RecursiveProvenanceTests(CliTestCase):
    def test_nested_archives_preserve_the_complete_source_chain(self) -> None:
        document = write_docx(
            self.root / "brief.docx",
            body=("This document is entirely synthetic.", FICTIONAL_SECRET),
            author=FICTIONAL_NAME,
        )
        inner = write_zip(
            self.root / "inner.zip",
            {"docs/brief.docx": document.read_bytes()},
        )
        outer = write_zip(
            self.root / "outer.zip",
            {"transfers/inner.zip": inner.read_bytes()},
        )

        result = self.run_cli("scan", outer, "--format", "json")

        self.assertEqual(result.returncode, 1, result.stderr)
        scan_findings = assert_scan_contract(result.json())
        self.assertTrue(
            scan_findings,
            "the synthetic token/metadata inside the nested document must be reported",
        )
        matching = [
            finding
            for finding in scan_findings
            if chain_contains_in_order(
                finding["source_chain"],
                ("outer.zip", "transfers/inner.zip", "docs/brief.docx"),
            )
            and any(
                part.endswith(("word/document.xml", "docProps/core.xml"))
                for part in finding["source_chain"]
            )
        ]
        self.assertTrue(
            matching,
            f"no finding retained archive and OOXML package layers: {scan_findings!r}",
        )

        self.assert_omits(FICTIONAL_SECRET, result.stdout, result.stderr)
        self.assert_omits(FICTIONAL_NAME, result.stdout, result.stderr)

    def test_provenance_uses_logical_names_not_temporary_extraction_paths(self) -> None:
        document = write_docx(self.root / "fixture.docx", body=(FICTIONAL_SECRET,))
        archive = write_zip(
            self.root / "named.zip",
            {"folder/fixture.docx": document.read_bytes()},
        )

        result = self.run_cli("scan", archive, "--format", "json")

        self.assertEqual(result.returncode, 1, result.stderr)
        scan_findings = assert_scan_contract(result.json())
        chains = "\n".join(part for finding in scan_findings for part in finding["source_chain"])
        self.assertIn("named.zip", chains)
        self.assertIn("folder/fixture.docx", chains)
        self.assertNotIn("process-tmp", chains)
        self.assertFalse(
            any(
                part.startswith("/tmp/")
                for finding in scan_findings
                for part in finding["source_chain"]
            )
        )


if __name__ == "__main__":
    unittest.main()
