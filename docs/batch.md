# Bounded batch preflight

Use `batch` to check several explicitly selected files or directories as one
local preflight. Nothing is uploaded, modified, packed, or automatically shared.
Each target gets its own scan and result; a failed target is never omitted.

```bash
sharelint batch ./handoff-a ./handoff-b ./attachment.zip
sharelint batch ./handoff-a ./handoff-b --format json -o batch.json
sharelint batch ./handoff-a ./handoff-b --format html -o batch.html
```

The aggregate report uses `t0001`, `t0002`, and so on in input order. It includes
per-target coverage/finding counts, rule/severity counts, effective limits,
content digests, and a digest of the ephemeral native scan report. It does not
include filenames, finding previews, matched-value fingerprints, or imported
free-form text. To investigate a target, run `sharelint scan` separately on that
input. A later scan has a fresh random report scope; its report digest will
normally differ. The aggregate is not an artifact receipt or a native report.

HTML is a standalone, script-free document with no remote resources. HTML
requires an explicit new output file. Outputs must be outside every selected
directory, different from every source, and must not already exist. Do not use
shell redirection into an input: the shell creates the destination before
ShareLint can inspect it.

## Reusable explicit lists

Create a private UTF-8 TOML file such as `handoffs.toml`:

```toml
schema_version = 1
targets = ["handoff-a", "handoff-b", "attachment.zip"]
```

```bash
sharelint batch --manifest handoffs.toml --profile public --format json -o batch.json
```

Relative paths are relative to the manifest's directory, not the current
working directory. No tilde, environment-variable, or glob expansion is done
inside a manifest. Choose either a manifest or positional paths, not both.
The manifest is bounded to 64 KiB, read without following its final-component
link, and accepts only the documented version and target list. It contains
real paths and should be protected; it is operator-selected control input, not
a sandbox for arbitrary third-party manifests.

Normalized duplicate paths are rejected before scanning. Overlapping directory
and file targets, or distinct filesystem aliases, are separate explicit inputs
and consume budget again. Targets are scanned sequentially in the given order;
this is not an atomic filesystem snapshot across targets.

## Resource limits and failure isolation

Defaults are 100 targets and 1 GiB of shared charged scan bytes. Override with
`--max-targets` (1–1000) and `--max-total-bytes` (positive signed 64-bit integer).
Each target still has all normal `ScanLimits`, configurable with explicit
`--config` and `--profile`. Its effective total-byte limit is reduced to the
remaining batch budget; it cannot grant itself more budget.

Charged bytes come from the scanner's exact input/decompression accounting,
not a sum of presentation surfaces that may describe the same bytes more than
once. This limits accounted inspection, not total system I/O, metadata probes,
hashing work, elapsed time, or Python memory. Existing bounded-reader sentinel
bytes and finite per-parser overhead still apply. Resource exhaustion is
visible as incomplete coverage; targets after exhaustion are explicitly
`not-scanned`. No parallel worker can overspend a shared counter.

A missing/unreadable target yields an `error` entry with a generic reason;
remaining targets are still attempted within budget. Ctrl+C aborts the command
with exit `130`, not a partially successful batch report. Atomic publication
of an already finished output may precede cancellation; inspect it before retrying.

## Exit codes and contract

- `0`: every target completed inspection and no finding met the threshold.
- `1`: at least one target was blocked, incomplete, or not scanned.
- `2`: a target had an operational input error, or arguments/control input/output
  were invalid. A mixed batch containing an error still reports its other results.
- `130`: cancelled.

Complete coverage is always required by `batch`; `strict = false` in a scan
configuration cannot weaken this requirement. A non-blocking finding can still
be present below the selected threshold. Passing is not a safety guarantee.

The separate [batch schema](../schemas/batch.schema.json) is version `1.0.0`.
Native reports and v2 pack receipts are unchanged. Python callers can use
`scan_batch([...], batch_limits=BatchLimits(...), limits=ScanLimits(...))` and
inspect `BatchResult.entries`, `.exit_code`, `.to_dict()`, or `.render()`.
