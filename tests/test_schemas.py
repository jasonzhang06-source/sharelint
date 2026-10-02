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
from sharelint.batch import BatchLimits, scan_batch
from sharelint.comparison import compare_reports
from sharelint.packing import PackBlocked, pack
from sharelint.planning import create_plan
from sharelint.redaction import create_redaction_plan
from sharelint.redaction_export import apply_redaction_plan
from sharelint.reporters import render_json
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

    def test_comparison_matches_its_separate_schema(self) -> None:
        target = self.root / "ordinary.txt"
        target.write_text("ordinary synthetic public text\n", encoding="utf-8")
        before = self.root / "before.json"
        after = self.root / "after.json"
        before.write_text(render_json(scan(target)), encoding="utf-8")
        target.write_text(FICTIONAL_SECRET, encoding="utf-8")
        after.write_text(render_json(scan(target)), encoding="utf-8")
        result = compare_reports(before, after).to_dict()
        validator = self.validator("comparison.schema.json")
        validator.validate(result)
        result["raw_evidence"] = "PRIVATE_MARKER"
        self.assertFalse(validator.is_valid(result))

    def test_batch_schema_covers_mixed_and_budget_limited_results(self) -> None:
        ordinary = self.root / "ordinary.txt"
        ordinary.write_text("ordinary synthetic text\n", encoding="utf-8")
        blocked = self.root / "blocked.txt"
        blocked.write_text(FICTIONAL_SECRET, encoding="utf-8")
        gap = self.root / "document.pdf"
        gap.write_bytes(b"%PDF-1.4\n%%EOF")
        validator = self.validator("batch.schema.json")
        for result in (
            scan_batch((ordinary,)),
            scan_batch((ordinary, blocked, gap, self.root / "absent")),
            scan_batch((ordinary, blocked), batch_limits=BatchLimits(max_total_bytes=2)),
        ):
            document = result.to_dict()
            validator.validate(document)
            document["entries"][0]["raw_path"] = "PRIVATE_MARKER"
            self.assertFalse(validator.is_valid(document))

    def test_plans_and_v2_receipts_match_separate_schemas(self) -> None:
        target = self.root / "ordinary.txt"
        target.write_text("ordinary synthetic public text\n", encoding="utf-8")
        plan = create_plan(target)
        self.validator("handoff-plan.schema.json").validate(plan.document)
        plan_path = self.root / "plan.json"
        plan_path.write_bytes(plan.payload)
        receipt = self.root / "receipt.json"
        pack(target, self.root / "planned.zip", receipt=receipt, plan=plan_path)
        document = json.loads(receipt.read_bytes())
        self.validator("receipt-v2.schema.json").validate(document)
        self.assertFalse(self.validator("receipt.schema.json").is_valid(document))
        document["plan"]["raw_report"] = {"private": "PRIVATE_MARKER"}
        self.assertFalse(self.validator("receipt-v2.schema.json").is_valid(document))

    def test_text_redaction_has_distinct_plan_and_receipt_schemas(self) -> None:
        source = self.root / "private.txt"
        source.write_text(FICTIONAL_SECRET + "\ncontact: person@example.test\n", encoding="utf-8")
        plan = create_redaction_plan(source)
        self.validator("redaction-plan.schema.json").validate(plan.document)
        plan_path = self.root / "redaction-plan.json"
        plan_path.write_bytes(plan.payload)
        artifact = apply_redaction_plan(source, plan_path, self.root / "redacted.txt")
        document = json.loads(artifact.receipt.read_bytes())
        self.validator("redaction-receipt.schema.json").validate(document)
        self.assertFalse(self.validator("receipt-v2.schema.json").is_valid(document))
        document["source"]["path"] = "PRIVATE_MARKER"
        self.assertFalse(self.validator("redaction-receipt.schema.json").is_valid(document))
        blocked = create_redaction_plan(source, rules=["SL.PII.EMAIL"])
        self.validator("redaction-plan.schema.json").validate(blocked.document)

    def test_packed_and_blocked_receipts_match_published_schema(self) -> None:
        validator = self.validator("receipt-v2.schema.json")
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
