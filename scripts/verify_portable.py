#!/usr/bin/env python3
"""Exercise a frozen ShareLint executable without importing its source package."""

from __future__ import annotations

import argparse
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

SYNTHETIC_SECRET = "AKIAIOSFODNN7EXAMPLE"


class VerificationError(RuntimeError):
    """Raised when a portable executable violates its release contract."""


@dataclass(frozen=True)
class Result:
    returncode: int
    stdout: str
    stderr: str


def _run(executable: Path, cwd: Path, environment: dict[str, str], *arguments: str) -> Result:
    try:
        completed = subprocess.run(
            [str(executable), *arguments],
            cwd=cwd,
            env=environment,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            timeout=45,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise VerificationError("the frozen executable could not complete a smoke test") from exc
    if SYNTHETIC_SECRET in completed.stdout or SYNTHETIC_SECRET in completed.stderr:
        raise VerificationError("the frozen executable exposed raw synthetic evidence")
    return Result(completed.returncode, completed.stdout, completed.stderr)


def _expect(result: Result, returncode: int, label: str) -> None:
    if result.returncode != returncode:
        raise VerificationError(
            f"{label} returned {result.returncode}; expected {returncode} "
            f"(stdout sha256:{hashlib.sha256(result.stdout.encode()).hexdigest()[:12]}, "
            f"stderr sha256:{hashlib.sha256(result.stderr.encode()).hexdigest()[:12]})"
        )


def _json(result: Result, label: str) -> dict[str, object]:
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise VerificationError(f"{label} did not emit one JSON document") from exc
    if not isinstance(payload, dict):
        raise VerificationError(f"{label} JSON root was not an object")
    return payload


def verify(executable: Path) -> None:
    if executable.is_symlink():
        raise VerificationError("executable must be a regular, non-symlink file")
    executable = executable.resolve()
    if not executable.is_file():
        raise VerificationError("executable must be a regular, non-symlink file")
    expected_version = importlib.metadata.version("sharelint")

    with tempfile.TemporaryDirectory(prefix="sharelint-portable-check-") as temporary_name:
        root = Path(temporary_name)
        work = root / "different cwd 空格 🚀"
        home = root / "isolated-home"
        temp = root / "isolated-temp"
        input_dir = root / "synthetic inputs 空格"
        output_dir = root / "outputs"
        for directory in (work, home, temp, input_dir, output_dir):
            directory.mkdir()
        environment = os.environ.copy()
        environment.update(
            {
                "HOME": str(home),
                "USERPROFILE": str(home),
                "TMPDIR": str(temp),
                "TEMP": str(temp),
                "TMP": str(temp),
                "PATH": "",
                "PYTHONHOME": str(root / "not-a-python-home"),
                "PYTHONPATH": str(root / "hostile-python-path"),
                "PYTHONHASHSEED": "947",
                "PYTHONDONTWRITEBYTECODE": "1",
                "NO_COLOR": "1",
                "LC_ALL": "C.UTF-8",
                "LANG": "C.UTF-8",
            }
        )

        version = _run(executable, work, environment, "--version")
        _expect(version, 0, "version")
        if version.stdout.strip() != f"ShareLint {expected_version}":
            raise VerificationError("frozen version does not match the installed wheel")

        rules = _run(executable, work, environment, "rules")
        _expect(rules, 0, "rules")
        if "SL.SECRET.AWS_ACCESS_KEY" not in rules.stdout:
            raise VerificationError("frozen rule catalog is incomplete")
        explained = _run(executable, work, environment, "explain", "SL.SECRET.AWS_ACCESS_KEY")
        _expect(explained, 0, "explain")

        clean = input_dir / "ordinary public sample.txt"
        clean.write_text("ordinary synthetic public text\n", encoding="utf-8")
        clean_result = _run(executable, work, environment, "scan", str(clean), "--format", "json")
        _expect(clean_result, 0, "clean scan")
        clean_payload = _json(clean_result, "clean scan")
        if clean_payload.get("findings") != []:
            raise VerificationError("clean frozen smoke fixture produced a finding")

        secret = input_dir / "credential.txt"
        secret.write_text(SYNTHETIC_SECRET + "\n", encoding="utf-8")
        secret_result = _run(executable, work, environment, "scan", str(secret), "--format", "json")
        _expect(secret_result, 1, "blocking scan")
        secret_payload = _json(secret_result, "blocking scan")
        if SYNTHETIC_SECRET in json.dumps(secret_payload, ensure_ascii=False):
            raise VerificationError("JSON report exposed raw synthetic evidence")
        findings = secret_payload.get("findings")
        if not isinstance(findings, list) or not any(
            isinstance(item, dict) and item.get("rule_id") == "SL.SECRET.AWS_ACCESS_KEY"
            for item in findings
        ):
            raise VerificationError("frozen scanner missed the synthetic secret")

        html_report = output_dir / "local-report.html"
        html_result = _run(
            executable,
            work,
            environment,
            "scan",
            str(secret),
            "--format",
            "html",
            "--output",
            str(html_report),
        )
        _expect(html_result, 1, "HTML report")
        html = html_report.read_text(encoding="utf-8")
        if not html.startswith("<!doctype html>") or SYNTHETIC_SECRET in html:
            raise VerificationError("frozen HTML report contract failed")

        malformed = input_dir / "malformed.zip"
        malformed.write_bytes(b"PK\x03\x04synthetic truncated archive")
        strict_result = _run(
            executable,
            work,
            environment,
            "scan",
            str(malformed),
            "--strict",
            "--format",
            "json",
        )
        _expect(strict_result, 1, "strict malformed scan")
        strict_payload = _json(strict_result, "strict malformed scan")
        summary = strict_payload.get("summary")
        if not isinstance(summary, dict) or summary.get("coverage_complete") is not False:
            raise VerificationError("strict malformed scan hid its coverage gap")

        demo_report = output_dir / "demo.json"
        demo_result = _run(
            executable,
            work,
            environment,
            "demo",
            "--format",
            "json",
            "--report",
            str(demo_report),
        )
        _expect(demo_result, 0, "demo")
        demo_payload = json.loads(demo_report.read_text(encoding="utf-8"))
        if not isinstance(demo_payload, dict) or not demo_payload.get("findings"):
            raise VerificationError("frozen demo did not produce its synthetic findings")

        pack_input = input_dir / "clean handoff"
        pack_input.mkdir()
        (pack_input / "read me.txt").write_text(
            "ordinary synthetic public text\n", encoding="utf-8"
        )
        bundle = output_dir / "safe-to-share.zip"
        receipt = output_dir / "private-receipt.json"
        report = output_dir / "private-report.json"
        packed = _run(
            executable,
            work,
            environment,
            "pack",
            str(pack_input),
            "--output",
            str(bundle),
            "--receipt",
            str(receipt),
            "--report",
            str(report),
        )
        _expect(packed, 0, "pack")
        if not zipfile.is_zipfile(bundle):
            raise VerificationError("frozen pack did not produce a ZIP archive")
        for document in (receipt, report):
            parsed = json.loads(document.read_text(encoding="utf-8"))
            if not isinstance(parsed, dict):
                raise VerificationError("frozen pack metadata root was not an object")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify a frozen ShareLint binary from a different, isolated working directory."
    )
    parser.add_argument("executable", type=Path)
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    try:
        verify(arguments.executable)
    except (VerificationError, importlib.metadata.PackageNotFoundError) as exc:
        print(f"portable verification failed: {exc}", file=sys.stderr)
        return 1
    print(f"Portable executable verified: {arguments.executable}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
