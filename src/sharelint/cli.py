"""Command-line interface for ShareLint."""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
from collections.abc import Sequence
from contextlib import suppress
from pathlib import Path

from . import __version__
from .demo import create_demo_bundle
from .models import Severity
from .packing import PackBlocked, PackError, pack
from .reporters import render, render_console
from .rules import RULES
from .scanner import ScanInputError, scan

FORMATS = ("console", "json", "sarif", "html")
_UNSAFE_TERMINAL_CODEPOINTS = {
    0x061C,
    0x200E,
    0x200F,
    *range(0x202A, 0x202F),
    *range(0x2066, 0x206A),
}


def _configure_standard_streams() -> None:
    """Emit stable UTF-8 when output is redirected on every supported platform."""

    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8", errors="backslashreplace")


def _severity(value: str) -> Severity:
    try:
        return Severity.parse(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sharelint",
        description="See what your files reveal before they leave your machine.",
    )
    parser.add_argument("--version", action="version", version=f"ShareLint {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="scan a file, folder, ZIP, or OOXML package")
    scan_parser.add_argument("target", type=Path)
    scan_parser.add_argument("--format", choices=FORMATS, default="console")
    scan_parser.add_argument("-o", "--output", type=Path)
    scan_parser.add_argument("--fail-on", type=_severity, default=Severity.HIGH)
    scan_parser.add_argument(
        "--strict",
        action="store_true",
        help="also fail when coverage is partial, skipped, or errored",
    )
    scan_parser.add_argument("--no-color", action="store_true")

    pack_parser = subparsers.add_parser(
        "pack", help="create a deterministic ZIP only when the policy passes"
    )
    pack_parser.add_argument("target", type=Path)
    pack_parser.add_argument("-o", "--output", type=Path, required=True)
    receipt_group = pack_parser.add_mutually_exclusive_group()
    receipt_group.add_argument("--receipt", type=Path)
    receipt_group.add_argument("--no-receipt", action="store_true")
    pack_parser.add_argument(
        "--report",
        type=Path,
        help="write the hash-bound JSON report here (requires --receipt)",
    )
    pack_parser.add_argument("--fail-on", type=_severity, default=Severity.HIGH)
    pack_parser.add_argument("--no-color", action="store_true")

    demo_parser = subparsers.add_parser("demo", help="scan a synthetic nested handoff bundle")
    demo_parser.add_argument(
        "-o",
        "--output",
        type=Path,
        metavar="BUNDLE",
        help="write the synthetic demo ZIP here",
    )
    demo_parser.add_argument(
        "--report",
        type=Path,
        metavar="REPORT",
        help="write the rendered demo report here",
    )
    demo_parser.add_argument("--format", choices=FORMATS, default="console")
    demo_parser.add_argument("--no-color", action="store_true")

    subparsers.add_parser("rules", help="list stable rule identifiers")
    explain_parser = subparsers.add_parser("explain", help="explain one rule")
    explain_parser.add_argument("rule_id")
    return parser


def _validate_scan_output(target: Path, output: Path | None) -> None:
    if output is None:
        return
    if output.exists() or output.is_symlink():
        raise ScanInputError("refusing to overwrite an existing report output")
    target_resolved = target.resolve()
    output_resolved = output.resolve()
    if output_resolved == target_resolved:
        raise ScanInputError("report output must differ from the scan target")
    if target.is_dir() and not target.is_symlink():
        try:
            output_resolved.relative_to(target_resolved)
        except ValueError:
            pass
        else:
            raise ScanInputError("report output must be outside the scanned directory")


def _write_or_print(content: str, output: Path | None) -> None:
    if output is None:
        sys.stdout.write(content)
        return
    if not output.parent.is_dir():
        raise ScanInputError("report output directory does not exist")
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            prefix=f".{output.name}.",
            suffix=".tmp",
            dir=output.parent,
            delete=False,
            mode="wb",
        ) as handle:
            temporary = Path(handle.name)
            handle.write(content.encode("utf-8"))
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, output)
    except FileExistsError as exc:
        raise ScanInputError("refusing to overwrite an existing report output") from exc
    except OSError as exc:
        raise ScanInputError("report output could not be written atomically") from exc
    finally:
        if temporary is not None:
            with suppress(OSError):
                temporary.unlink(missing_ok=True)


def _use_color(disabled: bool) -> bool:
    return not disabled and sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _display_path(path: Path) -> str:
    return "".join(
        f"\\u{code:04x}"
        if code < 0x20
        or code == 0x7F
        or 0xD800 <= code <= 0xDFFF
        or code in _UNSAFE_TERMINAL_CODEPOINTS
        else character
        for character in str(path)
        for code in (ord(character),)
    )


def _scan_command(arguments: argparse.Namespace) -> int:
    _validate_scan_output(arguments.target, arguments.output)
    report = scan(arguments.target)
    rendered = render(
        report,
        arguments.format,
        arguments.fail_on,
        color=_use_color(arguments.no_color) and arguments.output is None,
    )
    _write_or_print(rendered, arguments.output)
    blocked = report.count_at_or_above(arguments.fail_on) > 0
    if arguments.strict and report.has_coverage_gaps:
        blocked = True
    return 1 if blocked else 0


def _pack_command(arguments: argparse.Namespace) -> int:
    if arguments.report is not None and arguments.receipt is None:
        raise PackError("--report requires an explicit --receipt path")
    try:
        artifact = pack(
            arguments.target,
            arguments.output,
            receipt=arguments.receipt,
            report_output=arguments.report,
            write_receipt=not arguments.no_receipt,
            fail_on=arguments.fail_on,
        )
    except PackBlocked as exc:
        sys.stdout.write(
            render_console(exc.report, arguments.fail_on, color=_use_color(arguments.no_color))
        )
        messages = {
            "blocking_findings": "one or more findings met the blocking threshold",
            "coverage_incomplete": "one or more required surfaces were not fully inspected",
            "artifact_rescan_failed": "the completed archive did not pass its rescan",
            "source_changed": "the source changed during packing",
        }
        for reason in exc.reasons:
            sys.stderr.write(f"pack blocked: {messages.get(reason, reason)}\n")
        if exc.report_output is not None:
            sys.stdout.write(f"Wrote {_display_path(exc.report_output)}\n")
        if exc.receipt is not None:
            sys.stdout.write(f"Wrote {_display_path(exc.receipt)}\n")
        return 1
    sys.stdout.write(
        f"PACKED · {len(artifact.files)} file(s) · sha256:{artifact.archive_sha256}\n"
        f"Wrote {_display_path(artifact.output)}\n"
    )
    if artifact.report_output is not None:
        sys.stdout.write(f"Wrote {_display_path(artifact.report_output)}\n")
    if artifact.receipt is not None:
        sys.stdout.write(f"Wrote {_display_path(artifact.receipt)}\n")
    return 0


def _demo_command(arguments: argparse.Namespace) -> int:
    if arguments.report is not None:
        if arguments.report.exists() or arguments.report.is_symlink():
            raise ScanInputError("refusing to overwrite an existing report output")
        if not arguments.report.parent.is_dir():
            raise ScanInputError("report output directory does not exist")
    if (
        arguments.output is not None
        and arguments.report is not None
        and arguments.output.resolve() == arguments.report.resolve()
    ):
        raise ScanInputError("demo bundle and report output must use different paths")
    if arguments.output is not None:
        if arguments.output.exists() or arguments.output.is_symlink():
            raise ScanInputError("refusing to overwrite an existing demo bundle")
        try:
            create_demo_bundle(arguments.output)
        except FileExistsError as exc:
            raise ScanInputError("refusing to overwrite an existing demo bundle") from exc
        path = arguments.output
        report = scan(path)
        _write_or_print(
            render(
                report,
                arguments.format,
                Severity.HIGH,
                color=_use_color(arguments.no_color) and arguments.report is None,
            ),
            arguments.report,
        )
        return 0
    with tempfile.TemporaryDirectory(prefix="sharelint-demo-") as directory:
        path = create_demo_bundle(Path(directory) / "client-handoff.zip")
        report = scan(path)
        _write_or_print(
            render(
                report,
                arguments.format,
                Severity.HIGH,
                color=_use_color(arguments.no_color) and arguments.report is None,
            ),
            arguments.report,
        )
    return 0


def _rules_command() -> int:
    for rule_id in sorted(RULES):
        rule = RULES[rule_id]
        sys.stdout.write(f"{rule.severity.value.upper():8} {rule.rule_id:40} {rule.title}\n")
    return 0


def _explain_command(rule_id: str) -> int:
    rule = RULES.get(rule_id.upper())
    if rule is None:
        sys.stderr.write(f"unknown rule: {rule_id}\n")
        return 2
    sys.stdout.write(
        f"{rule.rule_id}\nSeverity: {rule.severity.value}\nTitle: {rule.title}\n"
        f"Tags: {', '.join(rule.tags)}\nRemediation: {rule.remediation}\n"
    )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    _configure_standard_streams()
    parser = _parser()
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "scan":
            return _scan_command(arguments)
        if arguments.command == "pack":
            return _pack_command(arguments)
        if arguments.command == "demo":
            return _demo_command(arguments)
        if arguments.command == "rules":
            return _rules_command()
        if arguments.command == "explain":
            return _explain_command(arguments.rule_id)
    except (ScanInputError, PackError, OSError) as exc:
        message = "operating system operation failed" if isinstance(exc, OSError) else str(exc)
        sys.stderr.write(f"sharelint: {message}\n")
        return 2
    parser.error("unknown command")
    return 2
