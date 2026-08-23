<div align="center">
  <img src="https://raw.githubusercontent.com/jasonzhang25-ship-it/sharelint/main/docs/assets/hero.svg" alt="ShareLint — local privacy preflight for everything you share" width="100%">
</div>

<p align="center">
  <strong>Gitleaks for everything you share.</strong><br>
  Inspect the whole handoff boundary—locally—before a file, folder, or archive leaves your machine.
</p>

<p align="center">
  <a href="#quick-start">Quick start</a> ·
  <a href="#what-it-checks">Coverage</a> ·
  <a href="https://github.com/jasonzhang25-ship-it/sharelint/blob/main/docs/threat-model.md">Threat model</a> ·
  <a href="https://github.com/jasonzhang25-ship-it/sharelint/blob/main/README.zh-CN.md">简体中文</a>
</p>

> [!IMPORTANT]
> **Alpha software.** ShareLint already has a working, dependency-free core, but its rules and
> format coverage are still growing. Use a tagged package when one is available or install from
> source, and independently review important results.

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

## Quick start

ShareLint requires Python 3.11 or newer. A source checkout works without runtime dependencies:

```bash
git clone https://github.com/jasonzhang25-ship-it/sharelint.git
cd sharelint
python -m pip install -e .
sharelint demo
```

After a tagged package is published, the equivalent installation is:

```bash
python -m pip install sharelint
```

The demo builds a disposable, entirely synthetic handoff bundle in a temporary directory. It shows
nested Office content, PDF metadata, active content, redacted evidence, and an explicit PDF coverage
gap without touching your files. Abridged output:

```text
ShareLint 0.1.0 · local privacy preflight
INCOMPLETE · 5 policy-blocking finding(s) · 9 total · 13 surface(s)
Coverage · 12 scanned · 1 partial · 0 skipped · 0 error(s)

CRITICAL SL.SECRET.AWS_ACCESS_KEY · AWS access key identifier
         client-handoff.zip -> deck.pptx -> ppt/embeddings/clients.xlsx
         evidence <secret:20 chars> [report-scoped fingerprint]

Coverage gaps
  PARTIAL client-handoff.zip -> report.pdf · rendered-page OCR is not enabled

Original untouched · 0 bytes uploaded · matched values hidden
A pass means no configured blocker was found on the listed surfaces; it is not a safety guarantee.
```

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
outside a scanned directory. `demo -o` follows the same non-overwrite rule.

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
[Rules and identifiers](https://github.com/jasonzhang25-ship-it/sharelint/blob/main/docs/rules.md) for stability and severity semantics.

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
[threat model](https://github.com/jasonzhang25-ship-it/sharelint/blob/main/docs/threat-model.md). Machine-output consumers should use the
[report and receipt contract](https://github.com/jasonzhang25-ship-it/sharelint/blob/main/docs/report-format.md), not parse console text.
JSON Schema files for automated validation live in [`schemas/`](https://github.com/jasonzhang25-ship-it/sharelint/tree/main/schemas).

## Project status and direction

ShareLint is at `0.1.0` **Alpha**. The current priority is to harden hostile-input handling, expand
synthetic fixtures, measure detector quality, and make release artifacts reproducible. Local OCR,
more regional PII rules, turnkey pre-send hooks, signed releases, and a desktop review experience
are later directions—not shipped claims. See the date-free [roadmap](https://github.com/jasonzhang25-ship-it/sharelint/blob/main/docs/roadmap.md).

The project stays useful by keeping three promises measurable: input remains local, evidence remains
hidden, and incomplete coverage never masquerades as a clean scan.

## Contributing and security

Issues and pull requests are welcome, especially for narrowly scoped format coverage, synthetic
regression fixtures, false-positive reductions, and hostile-input tests. Start with
[CONTRIBUTING.md](https://github.com/jasonzhang25-ship-it/sharelint/blob/main/CONTRIBUTING.md) and never attach real secrets or personal documents.

Report a possible vulnerability privately through GitHub's **Security → Report a vulnerability**
flow, as described in [SECURITY.md](https://github.com/jasonzhang25-ship-it/sharelint/blob/main/SECURITY.md). General help is covered by
[SUPPORT.md](https://github.com/jasonzhang25-ship-it/sharelint/blob/main/SUPPORT.md); project decisions follow [GOVERNANCE.md](https://github.com/jasonzhang25-ship-it/sharelint/blob/main/GOVERNANCE.md).

## License

[MIT](https://github.com/jasonzhang25-ship-it/sharelint/blob/main/LICENSE) © ShareLint contributors.
