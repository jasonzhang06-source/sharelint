"""Console, JSON, SARIF, and self-contained HTML report renderers."""

from __future__ import annotations

import html
import json
from collections import Counter
from typing import Any
from urllib.parse import quote

from .models import ScanReport, Severity
from .rules import RULES


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def render_json(report: ScanReport, threshold: Severity = Severity.HIGH) -> str:
    return (
        json.dumps(report.to_dict(threshold), ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    )


def _color(value: str, code: str, enabled: bool) -> str:
    return f"\x1b[{code}m{value}\x1b[0m" if enabled else value


def _terminal_safe(value: str) -> str:
    """Escape controls and bidi overrides before writing untrusted labels to a terminal."""

    unsafe = {
        0x061C,
        0x200E,
        0x200F,
        0x202A,
        0x202B,
        0x202C,
        0x202D,
        0x202E,
        0x2066,
        0x2067,
        0x2068,
        0x2069,
    }
    return "".join(
        f"\\u{code:04x}" if code < 0x20 or code == 0x7F or code in unsafe else character
        for character in value
        for code in (ord(character),)
    )


def render_console(
    report: ScanReport,
    threshold: Severity = Severity.HIGH,
    *,
    color: bool = False,
) -> str:
    summary = report.summary(threshold)
    verdict_label = str(summary["verdict"]).upper()
    verdict_code = {"PASS": "32;1", "BLOCKED": "31;1", "INCOMPLETE": "33;1"}[verdict_label]
    verdict = _color(verdict_label, verdict_code, color)
    lines = [
        f"ShareLint {report.tool_version} · local privacy preflight",
        (
            f"{verdict} · {summary['blocking_findings']} policy-blocking finding(s) "
            f"· {summary['total_findings']} total · {summary['surface_count']} surface(s)"
        ),
        (
            "Coverage · "
            f"{summary['surfaces_by_status']['scanned']} scanned · "
            f"{summary['surfaces_by_status']['partial']} partial · "
            f"{summary['surfaces_by_status']['skipped']} skipped · "
            f"{summary['error_count']} error(s)"
        ),
        f"Target · {_terminal_safe(report.target_name)} · sha256:{report.target_sha256[:16]}…",
    ]
    if report.findings:
        lines.append("")
        severity_colors = {
            Severity.CRITICAL: "35;1",
            Severity.HIGH: "31;1",
            Severity.MEDIUM: "33;1",
            Severity.LOW: "36",
            Severity.INFO: "2",
        }
        for finding in report.findings:
            label = _color(finding.severity.value.upper(), severity_colors[finding.severity], color)
            chain = " -> ".join(_terminal_safe(item) for item in finding.source_chain)
            lines.extend(
                [
                    f"{label:<8} {finding.rule_id} · {finding.title}",
                    f"         {chain} · {_terminal_safe(finding.location)}",
                    (
                        f"         evidence {finding.masked_preview} "
                        f"[{finding.evidence_fingerprint}]"
                    ),
                    f"         fix: {finding.remediation}",
                ]
            )
    gaps = [surface for surface in report.surfaces if surface.status.value != "scanned"]
    if gaps:
        lines.extend(["", "Coverage gaps"])
        for surface in gaps:
            lines.append(
                f"  {surface.status.value.upper():7} "
                f"{' -> '.join(_terminal_safe(item) for item in surface.source_chain)} · "
                f"{_terminal_safe(surface.note)}"
            )
    if report.errors:
        lines.extend(["", "Scan errors"])
        for error in report.errors:
            lines.append(
                f"  {error.code}: "
                f"{' -> '.join(_terminal_safe(item) for item in error.source_chain)} · "
                f"{_terminal_safe(error.message)}"
            )
    lines.extend(
        [
            "",
            "Original untouched · 0 bytes uploaded · matched values hidden",
            "A pass means no configured blocker was found on the listed surfaces; it is not a safety guarantee.",
        ]
    )
    return "\n".join(lines) + "\n"


def render_sarif(report: ScanReport, threshold: Severity = Severity.HIGH) -> str:
    used_rules = sorted(
        {finding.rule_id for finding in report.findings}
        | {error.code for error in report.errors if error.code in RULES}
    )
    rules = []
    for rule_id in used_rules:
        rule = RULES[rule_id]
        rules.append(
            {
                "id": rule.rule_id,
                "name": rule.rule_id.replace(".", "_"),
                "shortDescription": {"text": rule.title},
                "help": {"text": rule.remediation},
                "properties": {"tags": list(rule.tags), "defaultSeverity": rule.severity.value},
            }
        )
    level = {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
        Severity.INFO: "note",
    }
    results: list[dict[str, Any]] = []
    for finding in report.findings:
        uri = quote(finding.source_chain[0].replace("\\", "/"), safe="/._-")
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": level[finding.severity],
                "message": {"text": f"{finding.title}; evidence {finding.masked_preview}."},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}],
                "properties": {
                    "sharelint": {
                        "severity": finding.severity.value,
                        "sourceChain": list(finding.source_chain),
                        "location": finding.location,
                        "evidenceFingerprint": finding.evidence_fingerprint,
                        "fingerprintScope": report.fingerprint_scope,
                        "remediation": finding.remediation,
                    }
                },
            }
        )
    for error in report.errors:
        rule_id = error.code if error.code in RULES else "SL.SCAN.READ_ERROR"
        uri = quote(error.source_chain[0].replace("\\", "/"), safe="/._-")
        results.append(
            {
                "ruleId": rule_id,
                "level": "error",
                "message": {"text": error.message},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}],
                "properties": {
                    "sharelint": {
                        "coverageError": True,
                        "sourceChain": list(error.source_chain),
                    }
                },
            }
        )
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ShareLint",
                        "semanticVersion": report.tool_version,
                        "informationUri": "https://github.com/jasonzhang06-source/sharelint",
                        "rules": rules,
                    }
                },
                "artifacts": [
                    {
                        "location": {"uri": report.target_name},
                        "hashes": {"sha-256": report.target_sha256},
                    }
                ],
                "results": results,
                "invocations": [{"executionSuccessful": True}],
                "properties": {
                    "sharelint": {
                        "summary": report.summary(threshold),
                        "surfaces": [surface.to_dict() for surface in report.surfaces],
                        "limits": report.limits.to_dict(),
                        "targetSha256": report.target_sha256,
                        "fingerprintScope": report.fingerprint_scope,
                    }
                },
            }
        ],
    }
    return json.dumps(sarif, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def render_html(report: ScanReport, threshold: Severity = Severity.HIGH) -> str:
    summary = report.summary(threshold)
    verdict = str(summary["verdict"]).upper()
    tone = {"PASS": "good", "BLOCKED": "bad", "INCOMPLETE": "warn"}[verdict]
    counts = Counter(finding.severity.value for finding in report.findings)
    cards = "".join(
        f'<div class="metric"><b>{counts[severity.value]}</b><span>{severity.value}</span></div>'
        for severity in reversed(list(Severity))
    )
    findings = (
        "".join(
            (
                f'<article class="finding {finding.severity.value}">'
                f"<header><b>{html.escape(finding.severity.value.upper())}</b> "
                f"<code>{html.escape(finding.rule_id)}</code></header>"
                f"<h2>{html.escape(finding.title)}</h2>"
                f'<p class="path">{html.escape(" → ".join(finding.source_chain))}</p>'
                f"<p>{html.escape(finding.location)} · <code>{html.escape(finding.masked_preview)}</code></p>"
                f'<p class="fix">{html.escape(finding.remediation)}</p>'
                "</article>"
            )
            for finding in report.findings
        )
        or '<p class="empty">No configured findings on scanned surfaces.</p>'
    )
    gaps = (
        "".join(
            (
                "<li><b>"
                + html.escape(surface.status.value.upper())
                + "</b> "
                + html.escape(" → ".join(surface.source_chain))
                + " — "
                + html.escape(surface.note)
                + "</li>"
            )
            for surface in report.surfaces
            if surface.status.value != "scanned"
        )
        or "<li>None recorded.</li>"
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>ShareLint report · {html.escape(report.target_name)}</title>
<style>
:root{{--bg:#0c1118;--panel:#141c26;--text:#edf3f8;--muted:#9aabba;--line:#263341;--red:#ff667c;--green:#5de4a7;--amber:#ffc766;--blue:#72c7ff}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 ui-sans-serif,system-ui,sans-serif}}
main{{max-width:1050px;margin:auto;padding:56px 24px 90px}}.eyebrow{{color:var(--blue);font-weight:700;letter-spacing:.12em;text-transform:uppercase}}
h1{{font-size:clamp(36px,7vw,72px);line-height:1;margin:.2em 0}}.verdict{{display:inline-block;padding:7px 12px;border-radius:999px;font-weight:800}}
.verdict.bad{{background:#3a1720;color:var(--red)}}.verdict.good{{background:#123529;color:var(--green)}}.verdict.warn{{background:#3a2c11;color:var(--amber)}}.sub{{color:var(--muted);max-width:780px}}
.metrics{{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px;margin:28px 0}}.metric,.finding,.coverage{{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:18px}}
.metric b{{display:block;font-size:28px}}.metric span{{color:var(--muted);text-transform:capitalize}}.finding{{margin:12px 0;border-left-width:5px}}.finding.critical,.finding.high{{border-left-color:var(--red)}}.finding.medium{{border-left-color:var(--amber)}}.finding.low,.finding.info{{border-left-color:var(--blue)}}
.finding h2{{margin:.45em 0;font-size:20px}}code{{font-family:ui-monospace,SFMono-Regular,monospace;color:#b9d8ef}}.path,.fix,.empty{{color:var(--muted)}}
.coverage{{margin-top:30px}}li{{margin:.5em 0}}footer{{margin-top:36px;color:var(--muted);border-top:1px solid var(--line);padding-top:22px}}
</style></head><body><main>
<p class="eyebrow">ShareLint {html.escape(report.tool_version)} · local privacy preflight</p>
<h1>{html.escape(report.target_name)}</h1><span class="verdict {tone}">{verdict}</span>
<p class="sub">{summary["blocking_findings"]} policy-blocking finding(s) across {summary["surface_count"]} surface record(s). Target sha256:{html.escape(report.target_sha256)}</p>
<section class="metrics">{cards}</section><section>{findings}</section>
<section class="coverage"><h2>Coverage ledger</h2><p>{summary["surfaces_by_status"]["scanned"]} scanned · {summary["surfaces_by_status"]["partial"]} partial · {summary["surfaces_by_status"]["skipped"]} skipped · {summary["error_count"]} errors</p><ul>{gaps}</ul></section>
<footer>Original untouched · 0 bytes uploaded · matched values hidden.<br>A pass is scoped to configured rules and listed surfaces; it is not a safety guarantee.</footer>
</main></body></html>\n"""


def render(
    report: ScanReport,
    output_format: str,
    threshold: Severity = Severity.HIGH,
    *,
    color: bool = False,
) -> str:
    if output_format == "console":
        return render_console(report, threshold, color=color)
    if output_format == "json":
        return render_json(report, threshold)
    if output_format == "sarif":
        return render_sarif(report, threshold)
    if output_format == "html":
        return render_html(report, threshold)
    raise ValueError(f"unsupported output format: {output_format}")
