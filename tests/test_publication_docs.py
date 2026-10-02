"""Keep the public documentation aligned with the published release."""

import re
import unittest
from pathlib import Path

from sharelint import __version__

ROOT = Path(__file__).resolve().parents[1]
CURRENT = "3.0.0"
TAG = "v3.0.0"


class PublicationDocumentationTests(unittest.TestCase):
    def test_public_source_version(self) -> None:
        self.assertEqual(__version__, CURRENT)

    def test_bilingual_readmes_pin_installation_and_release_badge(self) -> None:
        for name in ("README.md", "README.zh-CN.md"):
            with self.subTest(name=name):
                text = (ROOT / name).read_text(encoding="utf-8")
                self.assertIn(f"pipx install 'sharelint=={CURRENT}'", text)
                self.assertIn(f"pipx install --force 'sharelint=={CURRENT}'", text)
                self.assertIn(f"uv tool install 'sharelint=={CURRENT}'", text)
                self.assertIn(f"uv tool install --force 'sharelint=={CURRENT}'", text)
                self.assertIn(
                    "pipx install 'git+https://github.com/"
                    f"jasonzhang06-source/sharelint.git@{TAG}'",
                    text,
                )
                self.assertIn(f"badge/release-{CURRENT}-", text)
                self.assertIn(f"https://pypi.org/project/sharelint/{CURRENT}/", text)
                self.assertNotIn("img.shields.io/pypi/v/sharelint", text)
                # v3 is wheel-only; native archives intentionally remain v2.
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

    def test_user_guides_select_only_the_current_pinned_package(self) -> None:
        paths = [ROOT / "README.md", ROOT / "README.zh-CN.md"]
        paths.extend(ROOT / "docs" / name for name in ("troubleshooting.md", "platform-support.md"))
        for path in paths:
            with self.subTest(path=path.name):
                text = path.read_text(encoding="utf-8")
                self.assertIn(f"sharelint=={CURRENT}", text)
                self.assertNotRegex(
                    text,
                    r"\b(?:pipx install|uv tool install|pip install)"
                    r"(?: --[\w-]+)* ['\"]?sharelint(?=[\s'\"`]|$)",
                )
                self.assertEqual(
                    set(re.findall(r"['\"]sharelint==([^'\"]+)['\"]", text)), {CURRENT}
                )
                self.assertNotIn("--from sharelint==", text)
                self.assertNotIn("uvx sharelint demo", text)
                self.assertNotRegex(text, r"\b(?:pipx|uv tool) upgrade sharelint\b")

    def test_current_docs_do_not_claim_unavailable_pypi_releases(self) -> None:
        paths = [ROOT / name for name in ("README.md", "README.zh-CN.md", "CHANGELOG.md")]
        paths.extend(
            ROOT / "docs" / name
            for name in (
                "README.md",
                "releasing.md",
                "platform-support.md",
                "roadmap.md",
                "troubleshooting.md",
                "expansion-plan.md",
                "releases/v2.0.0.md",
            )
        )
        for path in paths:
            with self.subTest(path=path.name):
                text = " ".join(path.read_text(encoding="utf-8").split())
                self.assertNotIn("PyPI currently provides 1.0.0", text)
                self.assertNotIn("PyPI does not provide 2.0.0", text)
                self.assertNotIn("2.0.0 is not currently available on PyPI", text)
                self.assertNotIn("PyPI 不提供 2.0.0", text)

    def test_release_notes_match_the_public_release(self) -> None:
        for path in (ROOT / "docs" / "releases").glob("v*.md"):
            match = re.fullmatch(r"v(\d+)\.(\d+)\.(\d+)", path.stem)
            self.assertIsNotNone(match)
            if match is not None:
                version = tuple(map(int, match.groups()))
                self.assertLessEqual(version, (3, 0, 0))
                if version == (3, 0, 0):
                    text = path.read_text(encoding="utf-8")
                    self.assertIn("redact plan", text)
                    self.assertIn("redact apply", text)
                if (1, 0, 0) < version < (3, 0, 0) and version != (2, 0, 0):
                    text = path.read_text(encoding="utf-8")
                    self.assertIn("Historical development record", text)
                    self.assertNotRegex(text, r"\b(?:pipx|uv tool) upgrade sharelint\b")
                    self.assertNotIn(f"blob/{path.stem}/", text)

        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertIn("## [3.0.0] - 2026-10-02 (publication)", changelog)
        self.assertIn("compare/v2.0.0...v3.0.0", changelog)
        self.assertIn("## [2.0.0] - 2026-09-14 (republication)", changelog)
        self.assertNotRegex(changelog, r"(?m)^## \[1\.[123]\.\d+\]")

    def test_publication_uses_the_personal_account(self) -> None:
        text = (ROOT / "docs" / "releasing.md").read_text(encoding="utf-8")
        self.assertIn("workflow is disabled", text)
        self.assertIn("Sign in as `jasonzhang06-source`", text)
        self.assertIn("`Jason_Zhang111`", text)
        self.assertIn("sharelint-3.0.0-1-py3-none-any.whl", text)
        self.assertIn("b84ef05cd4a46e99823e4d5d45d6ee721550490f0839fa7661b6cc7bb9564313", text)
        self.assertIn("wheel-only", text)
        self.assertIn("click **Publish release** yourself", text)


if __name__ == "__main__":
    unittest.main()
