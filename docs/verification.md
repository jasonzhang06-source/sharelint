# Offline receipt verification

ShareLint 1.2 adds an offline consistency check for the ZIP, private receipt,
and private JSON report created by `pack`. It never uploads any of them.

```sh
sharelint pack ./approved-files -o delivery.zip --receipt receipt.json --report report.json
sharelint verify delivery.zip --receipt receipt.json --report report.json
sharelint verify delivery.zip --receipt receipt.json --report report.json --format json
```

Use explicit paths. The verifier never opens filenames mentioned inside an
untrusted receipt or report, never extracts ZIP members, and does not overwrite
files. Receipts and reports contain contextual metadata: keep them private
unless the recipient is authorized to see that context.

## What is checked

- Supported receipt structure, exact field types, timestamp, and manifest paths.
- Exact report bytes against the recorded SHA-256, including whitespace.
- Native report structure and independently recomputed finding/coverage counts.
- Recorded policy digest, limits, threshold, tool version, and summary agreement.
- Exact ZIP bytes, size, and the report's target digest.
- Bounded in-memory ZIP inspection: canonical member names, unique sorted
  regular files, content sizes, CRC checks, and each manifest content digest.

For a blocked receipt, omit the ZIP argument. The report, policy, source
identity, and blocking reasons are checked, but the result stays `blocked`.
The verifier never turns a blocked pack into a passing artifact.

```sh
sharelint verify --receipt blocked.json --report blocked.report.json
```

## What is not proved

SHA-256 bindings detect inconsistencies, not a malicious replacement of all
three files. A receipt is not a signature. Verification does **not** establish
the producer's identity, prove the claimed original source contents, rerun
privacy detection, certify canonical ZIP metadata, or guarantee safe sharing.
The recorded ruleset digest is not automatically equated with today's ruleset.

If you obtained the receipt's SHA-256 through a separately trusted channel,
also pass `--expected-receipt-sha256` with that 64-character lowercase digest.
This pins the receipt bytes to your supplied value; it is still not a digital
signature. To reassess privacy under current rules, separately run
`sharelint scan delivery.zip --profile public`.

Imported names, previews, titles, notes, and claims are never echoed by the
verifier. Valid JSON cannot prove a third party actually masked its strings.

## Limits and exit codes

Receipt and report files are each capped at 16 MiB. JSON nesting is capped at
32, total scalar/container nodes at 500,000, individual strings at 262,144
characters, record arrays at 100,000, and source chains at 64 components.
Field-specific limits are tighter. Duplicate keys, non-finite numbers,
unpaired surrogates, links, non-regular files, and changing input identities
are rejected. Integers must fit a signed 64-bit nonnegative range.

ZIP budgets default to `ScanLimits`: 64 MiB compressed file, 32 MiB per member,
256 MiB total decompressed bytes, 10,000 members, and 200:1 compression ratio.
Use an operator-selected `--config` and optional `--profile` to change ZIP
resource budgets. A receipt cannot grant itself higher verifier limits.
Threshold and strictness in this configuration do not change the historical
policy being verified. No configuration is auto-discovered.

| Exit | Meaning |
| --- | --- |
| `0` | Packed artifact, report, and receipt passed the stated integrity checks |
| `1` | Integrity mismatch, archive verification failure, or a valid blocked receipt |
| `2` | Invalid/unsupported control document, missing argument, unsafe input, or document read limit |

`--format json` emits aggregate verification metadata and a fixed disclaimer.
Malformed-input errors use standard error and exit `2`, not a fabricated JSON
success document. Missing/unverified coverage is never interpreted as clean.

## Python

```python
from pathlib import Path
from sharelint import verify_receipt

result = verify_receipt(Path("receipt.json"), Path("report.json"), Path("delivery.zip"))
assert result.status == "verified"
```

Catch `sharelint.VerificationError` for mismatches and
`sharelint.input_io.DocumentInputError` for invalid/unreadable inputs.
Native report schema remains `1.0.0`. ShareLint 2.0 emits receipt schema `2.0.0`
with filename-free entry indices; this verifier accepts both receipt versions.
For a receipt bound to a handoff plan, also supply `plan_path=Path("plan.json")`
in Python or `--plan plan.json` on the CLI. The plan is mandatory when bound;
it is never opened through a path imported from a receipt. See [migration](migration-2.md).
