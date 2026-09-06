from __future__ import annotations

import json
import os
from unittest import mock

import tests.bootstrap  # noqa: F401
from sharelint.config import CONFIG_TEMPLATE, ConfigurationError, resolve_settings
from sharelint.input_io import DocumentInputError, read_document
from sharelint.models import ScanLimits, Severity
from tests.cli_harness import CliTestCase


class ConfigurationTests(CliTestCase):
    def test_defaults_and_builtin_profiles_preserve_their_semantics(self) -> None:
        default = resolve_settings()
        self.assertEqual(default.fail_on, Severity.HIGH)
        self.assertFalse(default.strict)
        self.assertEqual(default.limits, ScanLimits())
        self.assertEqual(resolve_settings(profile="public").fail_on, Severity.MEDIUM)
        self.assertTrue(resolve_settings(profile="public").strict)
        self.assertEqual(resolve_settings(profile="strict").fail_on, Severity.LOW)

    def test_config_template_is_valid_and_never_overwritten(self) -> None:
        target = self.root / "policy.toml"
        first = self.run_cli("config", "init", "-o", target)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(target.read_text(encoding="utf-8"), CONFIG_TEMPLATE)
        second = self.run_cli("config", "init", "-o", target)
        self.assertEqual(second.returncode, 2)
        settings = self.run_cli("config", "show", "--config", target, "--profile", "client")
        self.assertEqual(settings.returncode, 0, settings.stderr)
        self.assertEqual(settings.json()["fail_on"], "medium")
        self.assertTrue(settings.json()["pack_requires_complete_coverage"])
        self.assertNotIn(str(self.root), settings.stdout)

    def test_layering_limits_and_explicit_cli_overrides(self) -> None:
        config = self.root / "policy.toml"
        config.write_text(
            'schema_version = 1\ndefault_profile = "client"\n'
            '[scan]\nfail_on = "high"\nstrict = false\n'
            "[limits]\nmax_file_bytes = 4096\n"
            '[profiles.client]\nfail_on = "medium"\nstrict = true\n'
            "[profiles.client.limits]\nmax_member_bytes = 1024\n",
            encoding="utf-8",
        )
        settings = resolve_settings(config=config, fail_on=Severity.CRITICAL, strict=False)
        self.assertEqual(settings.profile, "client")
        self.assertEqual(settings.fail_on, Severity.CRITICAL)
        self.assertFalse(settings.strict)
        self.assertEqual(settings.limits.max_file_bytes, 4096)
        self.assertEqual(settings.limits.max_member_bytes, 1024)
        self.assertEqual(settings.limits.max_findings, ScanLimits().max_findings)

    def test_malformed_and_unknown_values_fail_without_echoing_content(self) -> None:
        config = self.root / "policy.toml"
        cases = (
            "",
            "schema_version = true",
            "schema_version = 2",
            "broken FICTITIOUS_VALUE",
            'schema_version = 1\nunknown = "FICTITIOUS_VALUE"',
            'schema_version = 1\n[scan]\nfail_on = "FICTITIOUS_VALUE"',
            'schema_version = 1\n[scan]\nstrict = "false"',
            "schema_version = 1\n[limits]\nmax_file_bytes = true",
            "schema_version = 1\n[limits]\nmax_member_bytes = 0",
            "schema_version = 1\n[limits]\nmax_compression_ratio = inf",
            "schema_version = 1\n[profiles.public]\nstrict = false",
            'schema_version = 1\n[profiles.client]\nignore = "*"',
            'schema_version = 1\ndefault_profile = "missing"',
            "schema_version = 1\n[profiles.client]\nstrict = false\nstrict = true",
        )
        for contents in cases:
            with self.subTest(case=cases.index(contents)):
                config.write_text(contents, encoding="utf-8")
                result = self.run_cli("config", "show", "--config", config)
                self.assertEqual(result.returncode, 2)
                self.assertNotIn("FICTITIOUS_VALUE", result.stderr)
                self.assertNotIn("Traceback", result.stderr)

    def test_unused_profile_is_validated(self) -> None:
        config = self.root / "policy.toml"
        config.write_text(
            'schema_version = 1\n[profiles.unused]\nstrict = "wrong"', encoding="utf-8"
        )
        with self.assertRaises(ConfigurationError):
            resolve_settings(config=config)

    def test_settings_apply_to_scan_and_pack_receipts(self) -> None:
        config = self.root / "policy.toml"
        config.write_text("schema_version = 1\n[limits]\nmax_file_bytes = 2048\n", encoding="utf-8")
        source = self.root / "ordinary.txt"
        source.write_text("public synthetic content\n", encoding="utf-8")
        result = self.run_cli("scan", source, "--config", config, "--format", "json")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.json()["scan"]["limits"]["max_file_bytes"], 2048)
        packed = self.run_cli("pack", source, "--config", config, "-o", self.root / "bundle.zip")
        self.assertEqual(packed.returncode, 0, packed.stderr)
        receipt = json.loads((self.root / "bundle.zip.sharelint.json").read_text(encoding="utf-8"))
        self.assertEqual(receipt["policy"]["limits"]["max_file_bytes"], 2048)
        self.assertTrue(receipt["policy"]["require_complete_coverage"])

    def test_limit_exhaustion_remains_a_coverage_gap(self) -> None:
        config = self.root / "policy.toml"
        config.write_text("schema_version = 1\n[limits]\nmax_file_bytes = 3\n", encoding="utf-8")
        source = self.root / "ordinary.txt"
        source.write_text("public synthetic content\n", encoding="utf-8")
        result = self.run_cli(
            "scan", source, "--config", config, "--profile", "public", "--format", "json"
        )
        self.assertEqual(result.returncode, 1)
        self.assertFalse(result.json()["summary"]["coverage_complete"])
        packed = self.run_cli("pack", source, "--config", config, "-o", self.root / "bundle.zip")
        self.assertEqual(packed.returncode, 1)
        self.assertFalse((self.root / "bundle.zip").exists())

    def test_configuration_is_not_auto_discovered_in_scan_target(self) -> None:
        source = self.root / "source"
        source.mkdir()
        (source / "sharelint.toml").write_text("invalid synthetic configuration", encoding="utf-8")
        result = self.run_cli("scan", source, "--format", "json")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.json()["summary"]["fail_on"], "high")

    def test_document_read_is_bounded_and_rejects_changed_identity(self) -> None:
        config = self.root / "policy.toml"
        config.write_bytes(b"synthetic")
        self.assertEqual(read_document(config, 9), b"synthetic")
        with self.assertRaises(DocumentInputError):
            read_document(config, 8)
        with self.assertRaises(DocumentInputError):
            read_document(self.root, 100)
        with (
            mock.patch("sharelint.input_io.metadata_matches_open_file", return_value=False),
            self.assertRaises(DocumentInputError),
        ):
            read_document(config, 100)
        link = self.root / "linked.toml"
        try:
            link.symlink_to(config)
        except OSError:
            return
        with self.assertRaises(DocumentInputError):
            read_document(link, 100)

    def test_fifo_and_oversized_control_documents_do_not_block(self) -> None:
        config = self.root / "huge.toml"
        config.write_bytes(b"#" * (64 * 1024 + 1))
        self.assertEqual(self.run_cli("config", "show", "--config", config).returncode, 2)
        if hasattr(os, "mkfifo"):
            fifo = self.root / "policy.fifo"
            os.mkfifo(fifo)
            with self.assertRaises(DocumentInputError):
                read_document(fifo, 100)
