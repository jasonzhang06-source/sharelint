from __future__ import annotations

import json
import unittest
from pathlib import Path

from tests.cli_harness import CliTestCase
from tests.contract import assert_scan_contract, sarif_results
from tests.helpers import (
    FICTIONAL_EMAIL,
    FICTIONAL_NAME,
    FICTIONAL_SECRET,
    write_docx,
    write_jpeg,
    write_pdf,
    write_png,
    write_pptx,
    write_xlsx,
)


def _write_corpus(root: Path, *, reverse: bool = False) -> None:
    builders = [
        ("document.docx", write_docx),
        ("sheet.xlsx", write_xlsx),
        ("slides.pptx", write_pptx),
        ("page.pdf", write_pdf),
        ("photo.jpg", write_jpeg),
        ("image.png", write_png),
    ]
    root.mkdir(parents=True)
    for name, builder in reversed(builders) if reverse else builders:
        builder(root / name)


def _stable_report(payload: dict, *, hide_target_name: bool = False) -> dict:
    """Remove only deliberately report-scoped anti-correlation values."""

    normalized = json.loads(json.dumps(payload))
    scan = normalized.get("scan", {})
    scan["fingerprint_scope"] = "<report-scoped>"
    target_name = scan.get("target", {}).get("name")
    if hide_target_name:
        scan.get("target", {})["name"] = "<target>"
    for finding in normalized.get("findings", []):
        finding["evidence_fingerprint"] = "<report-scoped>"
        if (
            hide_target_name
            and finding.get("source_chain")
            and finding["source_chain"][0] == target_name
        ):
            finding["source_chain"][0] = "<target>"
    for collection in ("surfaces", "errors"):
        for item in normalized.get(collection, []):
            if (
                hide_target_name
                and item.get("source_chain")
                and item["source_chain"][0] == target_name
            ):
                item["source_chain"][0] = "<target>"
    return normalized


def _paths_to_key(value: object, target: str, path: tuple[object, ...] = ()):
    if isinstance(value, dict):
        for key, nested in value.items():
            next_path = path + (key,)
            if key == target:
                yield next_path
            yield from _paths_to_key(nested, target, next_path)
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            yield from _paths_to_key(nested, target, path + (index,))


class PrivacyAndDeterminismTests(CliTestCase):
    def assert_no_raw_fixture_values(self, *streams: str) -> None:
        self.assert_omits(FICTIONAL_SECRET, *streams)
        self.assert_omits(FICTIONAL_EMAIL, *streams)
        self.assert_omits(FICTIONAL_NAME, *streams)

    def test_json_and_human_output_never_echo_sensitive_evidence(self) -> None:
        corpus = self.root / "corpus"
        _write_corpus(corpus)

        json_result = self.run_cli("scan", corpus, "--format", "json")
        text_result = self.run_cli("scan", corpus)

        self.assertEqual(json_result.returncode, 1, json_result.stderr)
        self.assertEqual(text_result.returncode, 1, text_result.stderr)
        scan_findings = assert_scan_contract(json_result.json())
        self.assertTrue(scan_findings, "fixtures contain synthetic secrets and metadata")
        self.assert_no_raw_fixture_values(
            json_result.stdout,
            json_result.stderr,
            text_result.stdout,
            text_result.stderr,
        )

    def test_sensitive_and_control_character_filename_is_never_echoed(self) -> None:
        corpus = self.root / "filename-corpus"
        corpus.mkdir()
        hostile_name = f"{FICTIONAL_EMAIL}\nFICTITIOUS_\x1b[31m.txt"
        (corpus / hostile_name).write_text("ordinary synthetic text\n", encoding="utf-8")

        json_result = self.run_cli("scan", corpus, "--format", "json")
        sarif_result = self.run_cli("scan", corpus, "--format", "sarif")
        console_result = self.run_cli("scan", corpus)

        for result in (json_result, sarif_result, console_result):
            self.assertEqual(result.returncode, 1)
        findings = assert_scan_contract(json_result.json())
        self.assertTrue(any(item["rule_id"] == "SL.PATH.EMAIL_IN_NAME" for item in findings))
        streams = tuple(
            result.stdout + result.stderr for result in (json_result, sarif_result, console_result)
        )
        self.assert_omits(FICTIONAL_EMAIL, *streams)
        self.assert_omits("\x1b", *streams)
        self.assert_omits("\\u001b", *(stream.lower() for stream in streams))
        self.assert_omits("%1b", *(stream.lower() for stream in streams))
        self.assert_omits("%0a", *(stream.lower() for stream in streams))

    def test_sensitive_path_label_is_masked_in_every_scan_format(self) -> None:
        corpus = self.root / "label-corpus"
        corpus.mkdir()
        (corpus / "secret.txt").write_text("ordinary synthetic text\n", encoding="utf-8")

        results = tuple(
            self.run_cli("scan", corpus, "--format", format_name)
            for format_name in ("json", "sarif", "html", "console")
        )

        for result in results:
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("secret.txt", result.stdout + result.stderr)
            self.assertIn("sensitive-label", result.stdout)

    def test_colliding_path_redactions_keep_distinct_provenance(self) -> None:
        corpus = self.root / "collision-corpus"
        corpus.mkdir()
        for name in ("secret.txt", "patient.txt"):
            (corpus / name).write_text(FICTIONAL_SECRET, encoding="utf-8")

        result = self.run_cli("scan", corpus, "--format", "json")

        self.assertEqual(result.returncode, 1, result.stderr)
        findings = assert_scan_contract(result.json())
        secret_findings = [item for item in findings if item["rule_id"] == "SL.SECRET.GITHUB_TOKEN"]
        self.assertEqual(len(secret_findings), 2)
        self.assertEqual(len({tuple(item["source_chain"]) for item in secret_findings}), 2)
        self.assertNotIn("secret.txt", result.stdout)
        self.assertNotIn("patient.txt", result.stdout)
        self.assertTrue(all("path-ref:" in item["source_chain"][-1] for item in secret_findings))

    def test_sarif_is_valid_relative_and_redacted(self) -> None:
        corpus = self.root / "corpus"
        _write_corpus(corpus)

        result = self.run_cli("scan", corpus, "--format", "sarif")

        self.assertEqual(result.returncode, 1, result.stderr)
        payload = result.json()
        results = sarif_results(payload)
        self.assertTrue(results)
        self.assert_no_raw_fixture_values(result.stdout, result.stderr)
        self.assertFalse(list(_paths_to_key(payload, "fingerprints")))
        self.assertFalse(list(_paths_to_key(payload, "partialFingerprints")))
        self.assertFalse(list(_paths_to_key(payload, "evidence_fingerprint")))
        scope_paths = list(_paths_to_key(payload, "fingerprintScope"))
        self.assertTrue(scope_paths)
        self.assertTrue(all("properties" in path[:-1] for path in scope_paths))
        for item in results:
            for location in item.get("locations", []):
                uri = (
                    location.get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")
                )
                self.assertIsInstance(uri, str)
                self.assertFalse(uri.startswith("/"))
                self.assertNotIn("process-tmp", uri)

    def test_scan_json_is_deterministic_except_scoped_fingerprints(self) -> None:
        corpus = self.root / "corpus"
        _write_corpus(corpus)

        first = self.run_cli("scan", corpus, "--format", "json")
        second = self.run_cli("scan", corpus, "--format", "json")

        self.assertEqual(first.returncode, 1)
        self.assertEqual(second.returncode, 1)
        self.assertEqual(first.stderr, second.stderr)
        self.assertEqual(_stable_report(first.json()), _stable_report(second.json()))

    def test_finding_order_is_independent_of_filesystem_creation_order(self) -> None:
        first_tree = self.root / "one"
        second_tree = self.root / "two"
        _write_corpus(first_tree, reverse=False)
        _write_corpus(second_tree, reverse=True)

        first = self.run_cli("scan", first_tree, "--format", "json")
        second = self.run_cli("scan", second_tree, "--format", "json")

        self.assertEqual(first.returncode, 1)
        self.assertEqual(second.returncode, 1)
        first_payload = first.json()
        second_payload = second.json()
        assert_scan_contract(first_payload)
        assert_scan_contract(second_payload)
        self.assertEqual(
            _stable_report(first_payload, hide_target_name=True),
            _stable_report(second_payload, hide_target_name=True),
        )


if __name__ == "__main__":
    unittest.main()
