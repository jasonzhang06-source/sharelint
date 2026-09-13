"""Keep the public documentation aligned with the published release."""

import re
import unittest
from pathlib import Path

from sharelint import __version__

ROOT = Path(__file__).resolve().parents[1]


class PublicationDocumentationTests(unittest.TestCase):
    def test_public_source_version(self) -> None:
        self.assertEqual(__version__, "2.0.0")

    def test_bilingual_readmes_pin_installation_and_release_badge(self) -> None:
        for name in ("README.md", "README.zh-CN.md"):
            with self.subTest(name=name):
                text = (ROOT / name).read_text(encoding="utf-8")
                self.assertIn(
                    "pipx install 'git+https://github.com/"
                    "jasonzhang06-source/sharelint.git@v2.0.0'",
                    text,
                )
                self.assertIn("badge/release-2.0.0-", text)
                self.assertNotIn("img.shields.io/pypi/v/sharelint", text)
                for target, extension in (
                    ("linux-glibc-x86_64", "tar.gz"),
                    ("windows-x86_64", "zip"),
                    ("macos-x86_64", "tar.gz"),
                    ("macos-arm64", "tar.gz"),
                ):
                    self.assertIn(
                        f"releases/download/v2.0.0/sharelint-v2.0.0-{target}.{extension}",
                        text,
                    )

    def test_user_guides_do_not_select_an_unpinned_package(self) -> None:
        paths = [ROOT / "README.md", ROOT / "README.zh-CN.md"]
        paths.extend(ROOT / "docs" / name for name in ("troubleshooting.md", "platform-support.md"))
        for path in paths:
            with self.subTest(path=path.name):
                text = path.read_text(encoding="utf-8")
                self.assertNotRegex(
                    text, r"\b(?:pipx install|uv tool install|pip install) sharelint\b"
                )
                self.assertNotIn("--from sharelint==", text)
                self.assertNotIn("uvx sharelint demo", text)
                self.assertNotRegex(text, r"\b(?:pipx|uv tool) upgrade sharelint\b")

    def test_release_notes_match_the_public_release(self) -> None:
        for path in (ROOT / "docs" / "releases").glob("v*.md"):
            match = re.fullmatch(r"v(\d+)\.(\d+)\.(\d+)", path.stem)
            self.assertIsNotNone(match)
            if match is not None:
                version = tuple(map(int, match.groups()))
                self.assertLessEqual(version, (2, 0, 0))
                if (1, 0, 0) < version < (2, 0, 0):
                    text = path.read_text(encoding="utf-8")
                    self.assertIn("Historical development record", text)
                    self.assertNotRegex(text, r"\b(?:pipx|uv tool) upgrade sharelint\b")
                    self.assertNotIn(f"blob/{path.stem}/", text)

        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertIn("## [2.0.0] - 2026-09-14 (republication)", changelog)
        self.assertIn("compare/v1.0.0...v2.0.0", changelog)
        self.assertNotRegex(changelog, r"(?m)^## \[1\.[123]\.\d+\]")

    def test_publication_uses_the_personal_account(self) -> None:
        text = (ROOT / "docs" / "releasing.md").read_text(encoding="utf-8")
        self.assertIn("workflow is disabled", text)
        self.assertIn("Sign in as `jasonzhang06-source`", text)
        self.assertIn("2dc9f29d0aed9fde3b1f37486f5bc8c8441a320e", text)
        self.assertIn("filenames cannot be reused", text)
        self.assertIn("Previous GitHub attestations were removed", text)


if __name__ == "__main__":
    unittest.main()
