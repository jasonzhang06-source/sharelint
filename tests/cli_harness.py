"""Dependency-free subprocess harness for public CLI contract tests."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class CliResult:
    args: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str

    def json(self) -> dict[str, Any]:
        try:
            value = json.loads(self.stdout)
        except json.JSONDecodeError as error:
            raise AssertionError(
                f"CLI did not emit a single JSON document: {error}\n"
                f"command: sharelint {self.args[3] if len(self.args) > 3 else '<none>'}\n"
                f"stdout: {len(self.stdout)} chars, sha256="
                f"{hashlib.sha256(self.stdout.encode()).hexdigest()[:12]}\n"
                f"stderr: {len(self.stderr)} chars, sha256="
                f"{hashlib.sha256(self.stderr.encode()).hexdigest()[:12]}"
            ) from error
        if not isinstance(value, dict):
            raise AssertionError(f"CLI JSON root must be an object, got {type(value).__name__}")
        return value


class CliTestCase(unittest.TestCase):
    """Give each test an isolated HOME, temp directory, and share boundary."""

    root: Path
    process_home: Path
    process_tmp: Path

    def setUp(self) -> None:
        super().setUp()
        temporary = tempfile.TemporaryDirectory(prefix="sharelint-tests-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.process_home = self.root / "process-home"
        self.process_tmp = self.root / "process-tmp"
        self.process_home.mkdir()
        self.process_tmp.mkdir()

    def run_cli(self, *args: object, timeout: float = 15.0) -> CliResult:
        command = (sys.executable, "-m", "sharelint", *(str(arg) for arg in args))
        env = os.environ.copy()
        import_paths = [str(REPO_ROOT / "src"), str(REPO_ROOT)]
        if env.get("PYTHONPATH"):
            import_paths.append(env["PYTHONPATH"])
        env.update(
            {
                "HOME": str(self.process_home),
                "TMPDIR": str(self.process_tmp),
                "PYTHONPATH": os.pathsep.join(import_paths),
                "LC_ALL": "C.UTF-8",
                "LANG": "C.UTF-8",
                "TZ": "UTC",
                "NO_COLOR": "1",
                "SOURCE_DATE_EPOCH": "0",
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONHASHSEED": "0",
            }
        )
        try:
            completed = subprocess.run(
                command,
                cwd=REPO_ROOT,
                env=env,
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            subcommand = str(args[0]) if args else "<none>"
            self.fail(
                f"sharelint {subcommand} exceeded {timeout:.1f}s "
                f"with {len(args)} argument(s); output was intentionally omitted"
            )
        return CliResult(
            args=tuple(command),
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )

    def assert_omits(self, prohibited: str, *streams: str) -> None:
        """Fail without copying potentially sensitive streams into test logs."""

        if any(prohibited in stream for stream in streams):
            marker = hashlib.sha256(prohibited.encode()).hexdigest()[:12]
            self.fail(f"output exposed prohibited fixture marker sha256:{marker}; output omitted")
