<div align="center">
  <img src="https://raw.githubusercontent.com/jasonzhang06-source/sharelint/main/docs/assets/hero.svg" alt="ShareLint — local privacy preflight for everything you share" width="100%">
</div>

<p align="center">
  <strong>Scan before you share.</strong><br>
  A local, fail-closed privacy preflight for files, folders, and nested archives.<br>
  Catch secrets, PII, speaker notes, hidden sheets, and location metadata without uploading them.
</p>

<p align="center">
  <a href="https://github.com/jasonzhang06-source/sharelint/actions/workflows/ci.yml"><img src="https://github.com/jasonzhang06-source/sharelint/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/jasonzhang06-source/sharelint/actions/workflows/codeql.yml"><img src="https://github.com/jasonzhang06-source/sharelint/actions/workflows/codeql.yml/badge.svg" alt="CodeQL"></a>
  <a href="https://pypi.org/project/sharelint/"><img src="https://img.shields.io/pypi/v/sharelint.svg" alt="PyPI version"></a>
  <img src="https://img.shields.io/badge/Python-3.11%2B-3776AB" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/Python_package_dependencies-0-38F2C2" alt="No third-party Python package dependencies">
  <a href="https://github.com/jasonzhang06-source/sharelint/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-54A9FF" alt="MIT license"></a>
</p>

<p align="center">
  <a href="#quick-start">Quick start</a> ·
  <a href="#what-it-checks">Coverage</a> ·
  <a href="https://github.com/jasonzhang06-source/sharelint/blob/main/docs/README.md">Docs</a> ·
  <a href="https://github.com/jasonzhang06-source/sharelint/blob/main/docs/threat-model.md">Threat model</a> ·
  <a href="https://github.com/jasonzhang06-source/sharelint/blob/main/README.zh-CN.md">简体中文</a>
</p>

## Quick start

### No Python: standalone archive

Download a matching archive from a completed
[GitHub Release](https://github.com/jasonzhang06-source/sharelint/releases). Standalone archives
include ShareLint and its Python runtime, so they do not require Python, pip, uv, or pipx on the
destination computer. The 1.0 release pipeline builds and verifies four native targets:

| Computer | Release target |
| --- | --- |
| x86-64 Linux with glibc | `linux-glibc-x86_64` |
| 64-bit Windows | `windows-x86_64` |
| Intel Mac | `macos-x86_64` |
| Apple silicon Mac | `macos-arm64` |

**Release v0.1.2 and earlier do not contain these standalone archives.** Use only files attached to
a completed release, not ordinary CI artifacts. Download the archive and its same-named `.sha256`
file, then follow the
[verification and first-run instructions](https://github.com/jasonzhang06-source/sharelint/blob/main/docs/troubleshooting.md#standalone-archive-verification).

### Run with uv

Alternatively, [uv](https://docs.astral.sh/uv/) can obtain a compatible Python automatically.
Install uv for your operating system, then
run the synthetic demo without persistently installing ShareLint:

```bash
uvx sharelint demo
```

For regular use, install the tool persistently and make its command available to a new shell:

```bash
uv tool install sharelint
uv tool update-shell
```

Open a new terminal after `uv tool update-shell`, then run `sharelint demo`. In the current shell,
`uvx sharelint demo` continues to work immediately.

If Python 3.11+ and [pipx](https://pipx.pypa.io/stable/) are already installed, pipx remains a
supported alternative:

```bash
pipx install sharelint
sharelint demo
```

Preview the same synthetic scan as a self-contained local HTML report:

```bash
sharelint demo --format html --report sharelint-demo.html
```

A standard virtual environment and `pip` also work. See the OS-specific
[installation and troubleshooting](https://github.com/jasonzhang06-source/sharelint/blob/main/docs/troubleshooting.md)
guide for installing uv from zero, standalone archive verification, upgrades, PATH fixes, and
externally managed Python environments.

For development, install from a source checkout:

```bash
git clone https://github.com/jasonzhang06-source/sharelint.git
cd sharelint
python -m pip install -e .
```

### Platform support

You do not need to switch operating systems to use or develop ShareLint. On Ubuntu, use the Linux
target or the Python package and let CI exercise the native Windows and macOS jobs. A standalone
binary is specific to its listed OS and architecture, so a Windows `.exe` does not run on Linux;
manual validation of Windows-only host behavior still requires a Windows host.

The Python 3.11+ package is tested on Ubuntu, Windows, and macOS. The standalone matrix covers
the four native targets listed above. Check the
[CI result](https://github.com/jasonzhang06-source/sharelint/actions/workflows/ci.yml) for the exact
commit or release you use. A configured target does not imply that every filesystem, OS version,
shell, locale, or security policy has been verified.

Writing reports, bundles, archives, and receipts requires hard-link support in
the destination filesystem so ShareLint can preserve its no-overwrite contract.
See [platform support](https://github.com/jasonzhang06-source/sharelint/blob/main/docs/platform-support.md)
for the validation matrix, Windows notes, and filesystem limitations.

> **ShareLint 1.0.** The existing scan, report, and pack workflow is now the stable release line.
> CLI exit codes and versioned JSON contracts remain compatible with 0.1.x. Format coverage is
> unchanged: PDF pages and image pixels are not OCR-scanned, and incomplete coverage blocks `pack`.
> See the [1.x compatibility policy](https://github.com/jasonzhang06-source/sharelint/blob/main/docs/stability.md).

You are about to send a ZIP. The code is clean, but the deck still has speaker notes, the workbook
contains a very-hidden sheet, the PDF names its author, and an image records a location. Git-focused
secret scanners do not see that entire boundary. ShareLint does.

It recursively follows a finding through nested containers, hides the matched value in every report,
and says when a surface was only partially inspected. Its `pack` command creates a deterministic ZIP
only after the configured policy and coverage checks pass, then reopens and rescans the output.

## Why ShareLint

Most tools inspect one layer of a handoff. ShareLint treats the selected file, directory, and every
supported nested container as one disclosure boundary:

| Approach | Strong at | What ShareLint adds |
| --- | --- | --- |
| Repository secret scanning | Credentials in source and history | Office/PDF/image surfaces, filenames, and nested delivery bundles |
| Metadata inspection or cleanup | Individual format fields | Cross-format provenance, content rules, and an explicit coverage ledger |
| Hosted DLP | Organization-wide policy and managed channels | A zero-upload personal preflight with no service or account |
| Manual ZIP review | Human context | Repeatable limits, masked evidence, output rescan, and hash-bound receipts |

It is intentionally composable with those controls rather than a replacement for all of them.

## Demo output

The demo builds a disposable, entirely synthetic handoff bundle in a temporary directory. Its
console output starts with a banner confirming that the data is synthetic and no personal files
were read. It shows nested Office content, PDF metadata, active content, redacted evidence, and an
explicit PDF coverage gap without touching your files. Abridged Linux output
(filesystem metadata surface counts may vary by platform):

```text
SYNTHETIC DEMO · generated sample only
No personal files were read; this run scanned only files created by ShareLint.

ShareLint 1.0.0 · local privacy preflight
INCOMPLETE · 5 policy-blocking finding(s) · 9 total · 14 surface(s)
Coverage · 13 scanned · 1 partial · 0 skipped · 0 error(s)

CRITICAL SL.SECRET.AWS_ACCESS_KEY · AWS access key identifier
         client-handoff.zip -> deck.pptx -> ppt/embeddings/clients.xlsx
         evidence <secret:20 chars> [report-scoped fingerprint]

Coverage gaps
  PARTIAL client-handoff.zip -> report.pdf · rendered-page OCR is not enabled

Original untouched · 0 bytes uploaded · matched values hidden
Incomplete means one or more listed surfaces were not fully inspected.
```

> Found it useful? [Star ShareLint](https://github.com/jasonzhang06-source/sharelint),
> [report a false positive](https://github.com/jasonzhang06-source/sharelint/issues/new?template=bug_report.yml),
> or [request a format](https://github.com/jasonzhang06-source/sharelint/issues/new?template=feature_request.yml).

## Use it

Scan a file, directory, ZIP, or Office document:

```bash
sharelint scan ./client-handoff
```

Write a machine-readable report or a static HTML review:

```bash
sharelint scan ./client-handoff --format json  -o sharelint.json
sharelint scan ./client-handoff --format sarif -o sharelint.sarif
sharelint scan ./client-handoff --format html  -o sharelint.html
```

Report outputs are owner-only where supported, never overwrite an existing path, and must sit
outside a scanned directory. `demo --report` follows the same rule; `demo -o` writes the reusable
synthetic ZIP bundle and also refuses to overwrite an existing path.

Make coverage gaps fail a normal scan in automation:

```bash
sharelint scan ./client-handoff --strict --fail-on high
```

Create a share bundle only if it passes the fail-closed gate:

```bash
sharelint pack ./approved-files -o release.zip
```

On success, this writes `release.zip`, the minimized receipt
`release.zip.sharelint.json`, and its exact companion report
`release.zip.sharelint.report.json`. The receipt binds the output hash, policy, measured coverage,
and companion report digest. On failure, no archive is published. An explicit
`--receipt blocked.json` may write `blocked.json` plus `blocked.report.json` for the blocked attempt;
it is never a success receipt. Companion reports include masked findings and contextual filenames,
so protect them as sensitive records even though matched values remain hidden. Successful receipts
also list archive member paths and should be protected alongside the archive.

`pack` always rejects partial, skipped, or errored coverage. There is deliberately no bypass flag:
a pack receipt is only meaningful when every required surface was inspected.

Discover the current rule set from the installed checkout:

```bash
sharelint rules
sharelint explain SL.OFFICE.NOTES
```

### Exit codes

| Code | Meaning |
| ---: | --- |
| `0` | Command completed and the selected gate did not block. |
| `1` | Findings met the threshold, strict coverage failed, or `pack` was blocked. |
| `2` | Invalid usage, unreadable input, or another operational error. |

`sharelint demo` intentionally returns `0` after rendering its synthetic blocked example.

The console and HTML report use `REVIEW` when a completed scan found something below the selected
`--fail-on` threshold. That is a prompt for human review, not a blocking verdict: the exit code is
still `0`, and JSON/SARIF keep `summary.verdict: "pass"` for the stable automation contract. `PASS`
means no findings were retained; neither label is a guarantee that the input is safe.

## What it checks

| Surface | Current inspection | Coverage semantics |
| --- | --- | --- |
| Directories | Stable recursive walk, path/name checks, regular files | Symlinks are not followed; skipped or unsupported entries stay visible. |
| ZIP archives | Bounded in-memory member inspection, archive/entry comments, extra fields, nested archives, path traversal, links, encryption, duplicates, bomb limits | Members are never extracted to disk. A limit, unreadable member, or unknown extra-field type is a gap. |
| Office Open XML | DOCX/XLSX/PPTX properties, comments, revisions, hidden text/sheets/slides, notes, external relationships, macros, custom XML, previews, embedded objects | OOXML receives the same archive limits; embedded packages retain their full source chain. |
| PDF | Static metadata, active-content markers, attachments, encryption, and incremental history | **Incomplete:** rendered pages are not OCR-scanned and no viewer is invoked. |
| Images | JPEG/PNG/WebP/TIFF metadata, including identity, device, text, and GPS fields where supported | **Incomplete:** pixels are not OCR-scanned; “metadata scanned” does not mean “image content scanned.” |
| Text | Common credentials, private-key markers, emails, US SSNs, payment cards, and revealing local paths | Pattern-based detection can have false positives and false negatives. |

Run `sharelint rules` for the installed rule registry and read
[Rules and identifiers](https://github.com/jasonzhang06-source/sharelint/blob/main/docs/rules.md) for stability and severity semantics.

## Designed around the share boundary

```text
files / folders / nested containers
                 │
                 ▼
        bounded local traversal
                 │
       ┌─────────┼──────────┐
       ▼         ▼          ▼
    secrets   document   coverage
      + PII    surfaces     gaps
       └─────────┼──────────┘
                 ▼
       privacy-safe findings
                 │
          scan ──┴── pack gate
                         │ pass only
                         ▼
               deterministic ZIP
                  + hash receipt
                  + output rescan
```

The core scan path has no network feature, telemetry, or runtime dependency outside Python's standard
library. It does not execute macros or JavaScript, invoke Office/PDF applications, follow external
relationships, or extract archive members to disk.

The [architecture guide](https://github.com/jasonzhang06-source/sharelint/blob/main/docs/architecture.md)
maps these guarantees to module boundaries and documents safe extension points for contributors.

Findings carry a nested logical source chain such as:

```text
handoff.zip -> deck.pptx -> ppt/embeddings/customers.xlsx -> xl/workbook.xml
```

Matched evidence is reduced immediately to a type-aware mask and a keyed, report-scoped fingerprint.
The ephemeral HMAC key is never serialized, so the fingerprint cannot be used as a stable
cross-report identifier. Reports are still sensitive because filenames, structure, finding types,
and counts can reveal context.

## What ShareLint does not promise

ShareLint is a preflight, not a proof system. A pass means only that no configured blocker was found
on the surfaces listed in that report under that policy.

- It cannot guarantee that a bundle is safe, anonymous, compliant, or free of sensitive data.
- It does not currently OCR PDF pages or image pixels.
- It does not sanitize or modify originals; fix issues in a share-specific copy, then rescan.
- It cannot determine whether a detected credential is live or whether personal data was intended.
- Unsupported, encrypted, malformed, or budget-limited content remains a visible coverage gap.

The security boundary and residual risks are documented in the
[threat model](https://github.com/jasonzhang06-source/sharelint/blob/main/docs/threat-model.md). Machine-output consumers should use the
[report and receipt contract](https://github.com/jasonzhang06-source/sharelint/blob/main/docs/report-format.md), not parse console text.
JSON Schema files for automated validation live in [`schemas/`](https://github.com/jasonzhang06-source/sharelint/tree/main/schemas).

## Project status and direction

ShareLint `1.0.0` stabilizes the existing local scanning and packaging workflow with clearer
first-run guidance and a validated release pipeline. The maintenance priority is focused fixes,
synthetic regression tests, and compatibility. Local OCR, policy exceptions, receipt verification,
pre-send hooks, and a desktop interface remain future work. See the
[roadmap](https://github.com/jasonzhang06-source/sharelint/blob/main/docs/roadmap.md).

The project stays useful by keeping three promises measurable: input remains local, evidence remains
hidden, and incomplete coverage never masquerades as a clean scan.

### Help shape the next release

The most useful early feedback is a real sharing workflow described with synthetic data: a format
that ShareLint cannot inspect yet, a false positive that can be reproduced safely, or a report that
was hard to act on. Open a focused [feature request](https://github.com/jasonzhang06-source/sharelint/issues/new?template=feature_request.yml)
or [bug report](https://github.com/jasonzhang06-source/sharelint/issues/new?template=bug_report.yml).
If ShareLint fits a problem you care about, starring the repository helps more people discover it.

## Contributing and security

Issues and pull requests are welcome, especially for narrowly scoped format coverage, synthetic
regression fixtures, false-positive reductions, and hostile-input tests. Start with
[CONTRIBUTING.md](https://github.com/jasonzhang06-source/sharelint/blob/main/CONTRIBUTING.md) and never attach real secrets or personal documents.

Report a possible vulnerability privately through GitHub's **Security → Report a vulnerability**
flow, as described in [SECURITY.md](https://github.com/jasonzhang06-source/sharelint/blob/main/SECURITY.md). General help is covered by
[SUPPORT.md](https://github.com/jasonzhang06-source/sharelint/blob/main/SUPPORT.md); project decisions follow [GOVERNANCE.md](https://github.com/jasonzhang06-source/sharelint/blob/main/GOVERNANCE.md).

## License

[MIT](https://github.com/jasonzhang06-source/sharelint/blob/main/LICENSE) © ShareLint contributors.
