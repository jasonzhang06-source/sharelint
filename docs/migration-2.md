# Migrating to ShareLint 2.0

The scanner, native report `1.0.0`, SARIF, configuration, existing commands, and
exit codes retain their contracts. New handoff-plan commands are optional.

## Receipt schema changes to 2.0.0

All new successful and explicitly requested blocked receipts use
`schema_version: "2.0.0"`. The old schema is retained at
[`receipt.schema.json`](../schemas/receipt.schema.json); new consumers use
[`receipt-v2.schema.json`](../schemas/receipt-v2.schema.json).

Successful receipt entries no longer repeat ZIP filenames. Version 1 receipts
could repeat a matched private filename if an operator deliberately relaxed
the blocking threshold. Version 2 removes that repetition:

```json
{"entry": 0, "size": 19, "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
```

`entry` is the zero-based position of a regular file in the canonical ZIP member
list. Entries are contiguous and in archive order. Size and SHA-256 refer to
uncompressed content. The exact archive digest still binds filenames, order,
metadata, and bytes; `verify` checks all of these without extracting an archive.
Do not interpret an entry number without the exact matching artifact.

Update consumers that read `files[].path` to accept both schema versions, or
use `sharelint verify`. ShareLint 2.0 verifies legacy v1 receipts; ShareLint 1.x
cannot verify v2 receipts. Original input files and ZIP member names are not
renamed or sanitized. A deliberately relaxed threshold can still allow
sensitive material into the artifact. Keep artifacts and companion reports
private until reviewed.

When `pack --plan` is used, a successful v2 receipt also has a `plan` object
binding the exact plan bytes, source boundary, and scan snapshot. Supply that
plan explicitly with `verify --plan`; omitting it is an error. Unplanned packs
have no plan binding, and blocked receipts never claim one. Neither a plan nor
an unsigned receipt authenticates a person or establishes approval.

`PackedArtifact.files` in the Python API remains internal-to-your-call file
metadata with member paths; the serialized receipt has the minimized v2 shape.
