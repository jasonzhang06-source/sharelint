from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:  # pragma: no cover - dependency-free source checks intentionally skip this
    Draft202012Validator = None  # type: ignore[assignment,misc]

import tests.bootstrap  # noqa: F401
from sharelint.packing import PackBlocked, pack
from sharelint.scanner import scan
from tests.helpers import FICTIONAL_SECRET


@unittest.skipUnless(Draft202012Validator is not None, "install the dev extra to validate schemas")
class SchemaContractTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="sharelint-schemas-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.repository = Path(__file__).resolve().parents[1]

    def validator(self, name: str):  # type: ignore[no-untyped-def]
        schema = json.loads((self.repository / "schemas" / name).read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        return Draft202012Validator(schema)

    def test_native_report_matches_published_schema(self) -> None:
        target = self.root / "ordinary.txt"
        target.write_text("ordinary synthetic public text\n", encoding="utf-8")

        self.validator("report.schema.json").validate(scan(target).to_dict())

    def test_packed_and_blocked_receipts_match_published_schema(self) -> None:
        validator = self.validator("receipt.schema.json")
        source = self.root / "source"
        source.mkdir()
        (source / "ordinary.txt").write_text("ordinary synthetic public text\n", encoding="utf-8")
        packed_receipt = self.root / "packed.json"
        pack(source, self.root / "bundle.zip", receipt=packed_receipt)
        validator.validate(json.loads(packed_receipt.read_text(encoding="utf-8")))

        (source / "blocked.txt").write_text(FICTIONAL_SECRET, encoding="utf-8")
        blocked_receipt = self.root / "blocked.json"
        with self.assertRaises(PackBlocked):
            pack(source, self.root / "blocked.zip", receipt=blocked_receipt)
        blocked_document = json.loads(blocked_receipt.read_text(encoding="utf-8"))
        validator.validate(blocked_document)

        with self.subTest("finding details are forbidden"):
            poisoned = dict(blocked_document)
            poisoned["findings"] = [{"masked_preview": "FICTITIOUS_RAW_VALUE"}]
            self.assertFalse(validator.is_valid(poisoned))
        with self.subTest("source paths are forbidden"):
            poisoned = dict(blocked_document)
            poisoned["source"] = {**blocked_document["source"], "absolute_path": "/private/path"}
            self.assertFalse(validator.is_valid(poisoned))


if __name__ == "__main__":
    unittest.main()
