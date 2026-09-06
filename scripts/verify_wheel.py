#!/usr/bin/env python3
"""Smoke-test an installed wheel from outside the source checkout."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import subprocess
import sys
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path


class WheelVerificationError(RuntimeError):
    """Raised when an installed wheel fails its first-run contract."""


@dataclass(frozen=True)
class Result:
    returncode: int
    stdout: str
    stderr: str


def _run(cwd: Path, environment: dict[str, str], *arguments: str) -> Result:
    try:
        completed = subprocess.run(
            [sys.executable, "-m", "sharelint", *arguments],
            cwd=cwd,
            env=environment,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise WheelVerificationError("installed wheel smoke test could not complete") from exc
    if "traceback" in (completed.stdout + completed.stderr).lower():
        raise WheelVerificationError("installed wheel exposed a traceback")
    return Result(completed.returncode, completed.stdout, completed.stderr)


def _expect(result: Result, returncode: int, label: str) -> None:
    if result.returncode != returncode:
        raise WheelVerificationError(
            f"{label} returned {result.returncode}; expected {returncode} "
            f"(stdout sha256:{hashlib.sha256(result.stdout.encode()).hexdigest()[:12]}, "
            f"stderr sha256:{hashlib.sha256(result.stderr.encode()).hexdigest()[:12]})"
        )


def verify() -> None:
    expected_version = importlib.metadata.version("sharelint")
    with tempfile.TemporaryDirectory(prefix="sharelint-wheel-check-") as temporary_name:
        root = Path(temporary_name)
        work = root / "different cwd 空格"
        home = root / "isolated-home"
        temp = root / "isolated-temp"
        inputs = root / "inputs"
        outputs = root / "outputs"
        for directory in (work, home, temp, inputs, outputs):
            directory.mkdir()
        environment = os.environ.copy()
        environment.pop("PYTHONHOME", None)
        environment.pop("PYTHONPATH", None)
        environment.update(
            {
                "HOME": str(home),
                "USERPROFILE": str(home),
                "TMPDIR": str(temp),
                "TEMP": str(temp),
                "TMP": str(temp),
                "NO_COLOR": "1",
                "PYTHONDONTWRITEBYTECODE": "1",
            }
        )

        version = _run(work, environment, "--version")
        _expect(version, 0, "version")
        if version.stdout.strip() != f"ShareLint {expected_version}":
            raise WheelVerificationError("installed wheel version is inconsistent")

        rules = _run(work, environment, "rules")
        _expect(rules, 0, "rules")
        if "SL.OFFICE.NOTES" not in rules.stdout:
            raise WheelVerificationError("installed wheel rule catalog is incomplete")

        demo = _run(work, environment, "demo")
        _expect(demo, 0, "demo")
        if "SYNTHETIC DEMO" not in demo.stdout or "No personal files were read" not in demo.stdout:
            raise WheelVerificationError("installed wheel demo boundary is unclear")

        demo_report = outputs / "demo.json"
        reported = _run(
            work,
            environment,
            "demo",
            "--format",
            "json",
            "--report",
            str(demo_report),
        )
        _expect(reported, 0, "demo report")
        payload = json.loads(demo_report.read_text(encoding="utf-8"))
        if not isinstance(payload, dict) or not payload.get("findings"):
            raise WheelVerificationError("installed wheel demo report is incomplete")

        handoff = inputs / "approved handoff"
        handoff.mkdir()
        (handoff / "read me.txt").write_text(
            "ordinary synthetic public-domain text\n", encoding="utf-8"
        )
        scanned = _run(work, environment, "scan", str(handoff), "--format", "json")
        _expect(scanned, 0, "clean scan")
        scan_payload = json.loads(scanned.stdout)
        if not isinstance(scan_payload, dict) or scan_payload.get("findings") != []:
            raise WheelVerificationError("installed wheel clean fixture produced findings")

        bundle = outputs / "shareable.zip"
        packed = _run(
            work,
            environment,
            "pack",
            str(handoff),
            "--output",
            str(bundle),
            "--no-receipt",
        )
        _expect(packed, 0, "clean pack")
        if not zipfile.is_zipfile(bundle) or "Shareable bundle" not in packed.stdout:
            raise WheelVerificationError("installed wheel did not complete a clean pack")


def main() -> int:
    try:
        verify()
    except (
        WheelVerificationError,
        importlib.metadata.PackageNotFoundError,
        json.JSONDecodeError,
        OSError,
    ) as exc:
        print(f"wheel verification failed: {exc}", file=sys.stderr)
        return 1
    print("Installed wheel verified from an isolated working directory")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
