"""Run the unittest contract and expose bounded failure details as CI annotations."""

from __future__ import annotations

import os
import unittest
from collections.abc import Iterable

_ANNOTATION_LIMIT = 6_000


def _annotation_escape(value: str) -> str:
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _annotate_failures(
    label: str,
    failures: Iterable[tuple[unittest.case.TestCase, str]],
) -> None:
    if os.environ.get("GITHUB_ACTIONS") != "true":
        return
    for test, details in failures:
        title = _annotation_escape(f"unittest {label}: {test.id()}")
        bounded_details = details[-_ANNOTATION_LIMIT:]
        print(f"::error title={title}::{_annotation_escape(bounded_details)}")


def main() -> int:
    suite = unittest.defaultTestLoader.discover("tests", top_level_dir=".")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    _annotate_failures("error", result.errors)
    _annotate_failures("failure", result.failures)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
