from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any
from unittest import mock

import tests.bootstrap  # noqa: F401
from sharelint.input_io import DocumentInputError
from sharelint.models import ScanLimits, Severity
from sharelint.redaction import create_redaction_plan, validate_output_name, validate_redaction_plan
from sharelint.reporters import canonical_json
from sharelint.scanner import scan
from sharelint.scanners.text import iter_text_matches
from sharelint.text_edits import (
    REDACTION_RULES,
    REPLACEMENT,
    apply_edits,
    decode_redaction_text,
    plan_edits,
    selected_rules,
    validate_edits,
)
from tests.cli_harness import CliTestCase
from tests.helpers import FICTIONAL_SECRET


class RedactionPlanTests(CliTestCase):
    def source(self, text: str, name: str = "private.txt") -> Path:
        path = self.root / name
        path.write_bytes(text.encode("utf-8"))
        return path

    def test_planning_preserves_original_and_contains_only_safe_edit_metadata(self) -> None:
        text = "你好\r\n" + FICTIONAL_SECRET + "\r\ncontact: person@example.test\r\n"
        source = self.source(text, "person@example.test.txt")
        original = source.read_bytes()
        plan = create_redaction_plan(source)
        self.assertTrue(plan.ready)
        self.assertEqual(source.read_bytes(), original)
        self.assertEqual(plan.document["source"]["sha256"], hashlib.sha256(original).hexdigest())
        self.assertEqual(plan.document["output"]["summary"]["total_findings"], 0)
        self.assertGreaterEqual(len(plan.document["edits"]), 2)
        for marker in (
            FICTIONAL_SECRET,
            "person@example.test",
            str(self.root),
            "masked_preview",
            "evidence_fingerprint",
        ):
            self.assertFalse(
                marker in plan.payload.decode(), "plan repeated private text or context"
            )
            self.assertFalse(marker in repr(plan), "plan representation exposed private text")
        rendered = apply_edits(text, plan.document["edits"]).decode()
        self.assertIn("你好\r\n", rendered)
        self.assertEqual(rendered.count("\r\n"), text.count("\r\n"))
        self.assertIn(REPLACEMENT, rendered)

    def test_literal_positions_work_with_unicode_repeated_matches_and_overlap(self) -> None:
        text = "你好 contact: person@example.test person@example.test\n" + FICTIONAL_SECRET
        edits = plan_edits(text, REDACTION_RULES, maximum=100)
        self.assertEqual(len(edits), 3)
        self.assertEqual(edits[0]["line"], 1)
        self.assertEqual(edits[-1]["line"], 2)
        self.assertEqual(
            validate_edits(edits, characters=len(text), rules=REDACTION_RULES, maximum=100), edits
        )
        for match in iter_text_matches(text):
            self.assertFalse(
                "person@example.test" in repr(match), "match objects must retain only offsets"
            )
        overlapping = "password=ghp_" + "AbCdEf0123456789" * 4
        edits = plan_edits(overlapping, REDACTION_RULES, maximum=100)
        self.assertEqual(len(edits), 1)
        self.assertEqual(
            set(edits[0]["rules"]), {"SL.SECRET.GENERIC_ASSIGNMENT", "SL.SECRET.GITHUB_TOKEN"}
        )
        self.assertEqual(apply_edits(overlapping, edits), b"password=[REDACTED]")

    def test_long_token_tails_are_removed_not_just_the_detector_prefix(self) -> None:
        for prefix in ("password=", "ghp_"):
            text = prefix + "AbCdEf0123456789" * 30
            edits = plan_edits(text, REDACTION_RULES, maximum=100)
            expected = b"password=[REDACTED]" if prefix == "password=" else b"[REDACTED]"
            self.assertEqual(apply_edits(text, edits), expected)

    def test_remaining_nonblocking_matches_still_block_derivative_publication(self) -> None:
        source = self.source(FICTIONAL_SECRET + "\ncontact: person@example.test")
        plan = create_redaction_plan(
            source, rules=["SL.SECRET.GITHUB_TOKEN"], fail_on=Severity.CRITICAL
        )
        self.assertFalse(plan.ready)
        self.assertIn("output-findings-remain", plan.document["reasons"])
        self.assertEqual(plan.document["output"]["summary"]["blocking_findings"], 0)

    def test_private_key_headers_are_never_treated_as_a_complete_key_removal(self) -> None:
        source = self.source(
            "-----BEGIN PRIVATE KEY-----\nSYNTHETIC-NOT-A-KEY\n-----END PRIVATE KEY-----\n"
        )
        plan = create_redaction_plan(source)
        self.assertFalse(plan.ready)
        self.assertTrue(plan.document["unsupported_private_key"])
        self.assertIn("private-key-redaction-unsupported", plan.document["reasons"])
        self.assertEqual(plan.document["edits"], [])
        self.assertNotIn("SYNTHETIC-NOT-A-KEY", plan.payload.decode())

    def test_unsupported_encodings_containers_controls_and_limits_fail_safely(self) -> None:
        target = self.source("ordinary text")
        for index, data in enumerate(
            (
                b"%PDF-1.4\n%%EOF",
                b"PK\x03\x04",
                b"\xff\xfea\x00",
                b"a\x00b",
                b"\xff",
                b"x" * (4 * 1024 * 1024 + 1),
            )
        ):
            target.write_bytes(data)
            with self.subTest(index=index), self.assertRaises(DocumentInputError):
                create_redaction_plan(target)
        target.write_bytes(b"ordinary text")
        with self.assertRaises(DocumentInputError):
            create_redaction_plan(target, limits=ScanLimits(max_file_bytes=2))
        with self.assertRaises(DocumentInputError):
            decode_redaction_text(b"abcd", 2)
        with self.assertRaises(DocumentInputError):
            decode_redaction_text(b"x" * (4 * 1024 * 1024 + 1), 8_000_000)

    def test_exact_character_limit_is_blocked_instead_of_claiming_complete_coverage(self) -> None:
        target = self.source("abc")
        plan = create_redaction_plan(target, limits=ScanLimits(max_text_chars=3))
        self.assertFalse(plan.ready)
        self.assertIn("source-coverage-gap", plan.document["reasons"])
        self.assertIn("output-coverage-gap", plan.document["reasons"])

    def test_replacement_growth_and_source_snapshot_mismatch_are_rejected(self) -> None:
        target = self.source("a@b.co")
        with self.assertRaises(DocumentInputError):
            create_redaction_plan(target, limits=ScanLimits(max_file_bytes=6))
        mismatched = scan(target)
        mismatched.target_sha256 = "0" * 64
        with (
            mock.patch("sharelint.redaction.scan", return_value=mismatched),
            self.assertRaises(DocumentInputError),
        ):
            create_redaction_plan(target)

    def test_output_name_and_rule_selections_are_strict(self) -> None:
        for name in (
            "../escape.txt",
            "/tmp/file",
            "a/b",
            "a\\b",
            "CON.txt",
            "NUL",
            "trailing.",
            "a\0b",
            "",
            "a" * 129,
        ):
            with self.subTest(length=len(name)), self.assertRaises(DocumentInputError):
                validate_output_name(name)
        self.assertEqual(validate_output_name("输出.txt"), "输出.txt")
        for rules in (
            (),
            ("unknown",),
            ("SL.PII.EMAIL", "SL.PII.EMAIL"),
            "SL.PII.EMAIL",
            ("SL.SECRET.PRIVATE_KEY",),
        ):
            with self.subTest(kind=type(rules).__name__), self.assertRaises(DocumentInputError):
                selected_rules(rules)

    def test_excessive_candidate_count_is_not_silently_truncated(self) -> None:
        text = "person@example.test\n" * 3
        with self.assertRaises(DocumentInputError):
            plan_edits(text, REDACTION_RULES, maximum=2)
        for maximum in (0, True, 10001):
            with self.assertRaises(DocumentInputError):
                plan_edits(text, REDACTION_RULES, maximum=maximum)

    def test_plan_validation_rejects_tampering_and_unsafe_edit_shapes(self) -> None:
        plan = create_redaction_plan(self.source("person@example.test\n"))
        original = plan.document
        cases = []
        for key, value in (
            ("schema_version", "9.0.0"),
            ("raw_source", "PRIVATE_MARKER"),
            ("created_at", "2026-99-01T00:00:00Z"),
            ("unsupported_private_key", 1),
        ):
            modified = copy.deepcopy(original)
            modified[key] = value
            cases.append(modified)
        for key, value in (
            ("start", -1),
            ("end", 999),
            ("line", 0),
            ("replacement", "PRIVATE_MARKER"),
            ("rules", ["unknown"]),
        ):
            modified = copy.deepcopy(original)
            modified["edits"][0][key] = value
            cases.append(modified)
        modified = copy.deepcopy(original)
        modified["source"]["summary"]["total_findings"] += 1
        cases.append(modified)
        for index, value in enumerate(cases):
            with self.subTest(index=index), self.assertRaises(DocumentInputError):
                validate_redaction_plan(json.dumps(value).encode())
        self.assertEqual(validate_redaction_plan(plan.payload).sha256, plan.sha256)

    def test_nested_type_mutations_fail_without_raw_parser_exceptions(self) -> None:
        plan = create_redaction_plan(self.source("person@example.test\n"))

        def paths(value: Any, prefix: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
            result: list[tuple[Any, ...]] = []
            entries = (
                value.items()
                if isinstance(value, dict)
                else enumerate(value)
                if isinstance(value, list)
                else ()
            )
            for key, child in entries:
                result.append((*prefix, key))
                result.extend(paths(child, (*prefix, key)))
            return result

        for keys in paths(plan.document):
            for replacement in (None, True, False, -1, 0, 1, 1.5, [], {}, "", "PRIVATE_MARKER"):
                document = copy.deepcopy(plan.document)
                parent = document
                for key in keys[:-1]:
                    parent = parent[key]
                parent[keys[-1]] = replacement
                with self.subTest(field=keys, replacement_type=type(replacement).__name__):
                    try:
                        validate_redaction_plan(json.dumps(document).encode())
                    except DocumentInputError as exc:
                        self.assertNotIn("PRIVATE_MARKER", str(exc))

    def test_recomputed_checksum_is_not_a_substitute_for_fresh_application_checks(self) -> None:
        from sharelint.redaction_export import apply_redaction_plan

        source = self.source("person@example.test\n")
        plan = create_redaction_plan(source)
        tampered = copy.deepcopy(plan.document)
        tampered["edits"] = []
        tampered["document_sha256"] = hashlib.sha256(
            canonical_json(
                {key: value for key, value in tampered.items() if key != "document_sha256"}
            ).encode()
        ).hexdigest()
        payload = json.dumps(tampered).encode()
        self.assertTrue(validate_redaction_plan(payload).ready)
        path = self.root / "tampered-plan.json"
        path.write_bytes(payload)
        output = self.root / "redacted.txt"
        with self.assertRaises(DocumentInputError):
            apply_redaction_plan(source, path, output)
        self.assertFalse(output.exists())
