# Architecture

This guide explains how ShareLint turns untrusted local files into bounded,
privacy-safe results. It is intended for contributors changing more than one
module. The [threat model](threat-model.md) remains authoritative for security
requirements, and the [report contract](report-format.md) remains authoritative
for serialized output.

## Boundaries

The installed package has no third-party runtime dependencies and supports
Python 3.11 or newer. Its trusted computing base is the Python interpreter,
standard library, operating system, installed ShareLint release, and the policy
chosen by the operator. Every selected path, filename, byte stream, archive
header, document part, and embedded object is untrusted.

The core scan path must remain local. It has no network client, telemetry path,
or remote parser. Format handlers inspect bytes as data: they do not execute
macros or active content, launch viewers, resolve external relationships, or
extract archive members to disk.

## Data flow

```text
CLI or Python caller
        │
        ▼
 scanner.scan(target, limits)
        │
        ├── bounded filesystem traversal
        └── content-aware byte dispatch
                    │
          ┌─────────┼───────────┐
          ▼         ▼           ▼
       archive    document     text/path
       + OOXML    + metadata   detectors
          └─────────┼───────────┘
                    ▼
              ScanContext
       findings + surfaces + errors
                    │
                    ▼
               ScanReport
          ┌─────────┴───────────┐
          ▼                     ▼
       renderers          strict pack gate
   console/JSON/SARIF/HTML       │ pass only
                                ▼
                      deterministic ZIP
                      + reopened rescan
                      + hash-bound receipt
```

Detection and coverage are separate ledgers. A detector may find nothing while
a required surface remains partial or skipped. That condition is incomplete,
not clean. Renderers and `pack` consume the same `ScanReport`; they must not
reconstruct coverage from finding counts.

## Module map

| Module | Responsibility | Must not do |
| --- | --- | --- |
| `cli.py` | Parse commands, validate output paths, select renderers, and map results to stable exit codes | Interpret document bytes or weaken `pack` policy |
| `scanner.py` | Safely open top-level inputs, traverse directories, dispatch bounded bytes, and assemble a report | Follow symlinks or silently discard unsupported input |
| `filesystem.py` | Provide stable, bounded directory enumeration shared by scanning and packing | Read file contents or leak platform exception text |
| `scanners/detect.py` | Identify supported content from bytes with suffixes used only as hints | Treat a filename extension as proof of format |
| `scanners/archive.py` | Inspect ZIP/OOXML members recursively through bounded in-memory streams | Extract members to disk or reset nested resource counters |
| `scanners/ooxml.py` | Inspect recognized Office package parts and structural privacy surfaces | Execute active content or resolve external relationships |
| `scanners/pdf.py` | Inspect documented static PDF metadata and active-content markers | Claim rendered-page or OCR coverage |
| `scanners/image.py` | Inspect recognized image metadata and embedded metadata structures | Claim pixel or OCR coverage |
| `scanners/text.py` and `scanners/path.py` | Apply deterministic secret, PII, and path-name rules | Send evidence directly to an output renderer |
| `context.py` | Enforce session limits, deduplicate findings, mask evidence, and record coverage/errors | Store raw evidence in `Finding` objects |
| `rules.py` | Define stable rule IDs, severities, titles, remediations, and tags | Contain parser-specific mutable state |
| `models.py` | Define the public in-memory contracts and verdict semantics | Perform format parsing or output-specific escaping |
| `privacy.py` | Produce bounded masks and report-scoped keyed fingerprints | Serialize the ephemeral fingerprint key |
| `reporters.py` | Render console, native JSON, SARIF, and self-contained HTML | Reveal raw evidence or reinterpret an incomplete report as passing |
| `packing.py` | Enforce the strict gate, build deterministic ZIPs, rescan output, and publish receipts atomically | Publish on partial coverage or overwrite an existing output |
| `demo.py` | Build the deterministic, entirely synthetic demonstration bundle | Read user documents or embed live credentials |

## Scan lifecycle

1. `scan()` validates the top-level object without following a symlink and
   creates one `ScanContext` with finite `ScanLimits`.
2. Paths are checked before content is opened. Display paths are masked when a
   path itself contains sensitive evidence.
3. Regular files are opened with platform safety flags where available. File
   identity and size are checked around the bounded read.
4. `scan_blob()` detects content and dispatches it. Nested archives reuse the
   same context so depth, expanded bytes, member count, and finding limits apply
   across the complete sharing boundary.
5. Scanners add findings only through `ScanContext.add_finding()`. That method
   resolves the rule, masks evidence immediately, and records only a
   report-scoped fingerprint.
6. Every recognized or attempted surface receives a `scanned`, `partial`, or
   `skipped` record. Parser and I/O failures receive bounded, content-free error
   messages.
7. The context becomes a structured `ScanReport`. Verdict precedence is
   incomplete coverage, then blocking findings, then pass.

## Pack lifecycle

`pack()` deliberately repeats work to bind the published bytes to the policy:

1. Scan the source under the effective limits and severity threshold.
2. Refuse to continue if a blocking finding, error, partial surface, or skipped
   surface exists.
3. Write selected regular files into a deterministic ZIP in a private temporary
   location.
4. Close and reopen the completed ZIP, then verify that its member manifest
   matches the bytes selected for the archive.
5. Scan the completed ZIP as untrusted input and require complete,
   non-blocking coverage again.
6. Rescan the source and require its target digest to match the initial scan.
7. Hash the exact archive and native report, construct the minimized receipt,
   and publish all requested outputs without overwriting existing paths.

A blocked-attempt receipt is optional and is never a success receipt. The
companion report remains sensitive even though matched values are masked.

## Stable contracts

Changes to these surfaces require compatibility review and tests:

- rule IDs and their security meaning;
- CLI commands, exit codes, and overwrite behavior;
- `ScanReport` verdict and coverage semantics;
- native report and receipt schemas;
- deterministic archive and receipt profiles;
- masking guarantees and fingerprint scope;
- default resource limits and Python support range.

Version serialized formats according to [report-format.md](report-format.md).
Document user-visible rule changes in [rules.md](rules.md) and the changelog.

## Safe extension checklist

For a new scanner or format surface:

1. Detect from bounded bytes; treat extensions as hints.
2. Reuse the caller's `ScanContext` and its cumulative limits.
3. Add findings only through the context and use synthetic evidence in tests.
4. Record every attempted surface, including unsupported, malformed, encrypted,
   truncated, and budget-limited cases.
5. Return a coverage gap whenever required inspection did not complete.
6. Add nominal, malformed-input, false-positive, limit, masking, nested-source,
   and reporter regression tests as applicable.
7. Update the README coverage table, rules documentation, threat model when the
   boundary changes, and both user-facing languages.

For a new rule, follow the stricter checklist in
[Adding or changing a rule](rules.md#adding-or-changing-a-rule). For a new
renderer, treat every string in a report as potentially sensitive and
untrusted, preserve verdict semantics exactly, and add an output-level test that
proves the complete matched value is absent.
