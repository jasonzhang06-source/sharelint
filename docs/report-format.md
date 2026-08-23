# Report and receipt formats

ShareLint has three machine-readable output contracts:

- the native JSON scan report, which preserves ShareLint coverage semantics;
- SARIF 2.1.0, for code-scanning integrations;
- the compact `pack` receipt, which binds an exported artifact to its report and
  effective scan configuration.

The native report is authoritative. SARIF is a projection and the receipt is an
integrity summary, not a replacement for the report.

Draft 2020-12 schemas are published as
[`schemas/report.schema.json`](../schemas/report.schema.json) and
[`schemas/receipt.schema.json`](../schemas/receipt.schema.json).

## Common requirements

All formats are UTF-8 JSON. Producers MUST NOT emit NaN, infinity, duplicate
object keys, raw matched evidence, or unescaped control characters. SHA-256
fields contain exactly 64 lowercase hexadecimal characters. Evidence
fingerprints use the separate `hmac-sha256:` format described below.

Files SHOULD be created with owner-only permissions where supported. Writing a
report to stdout is an explicit choice by the caller; ShareLint cannot control
terminal scrollback, shell redirection, CI capture, or a downstream upload.

`schema_version` uses `MAJOR.MINOR.PATCH`:

- additive fields and enum values increment `MINOR`;
- clarifications and compatible corrections increment `PATCH`;
- removal, renaming, type changes, or changed security meaning increment
  `MAJOR`.

A consumer MUST reject an unsupported major version. Within a supported major,
native-report and SARIF consumers SHOULD ignore unknown object members but MUST
treat an unknown coverage status, digest algorithm, or verdict conservatively.
Receipt schema `1.0.0` deliberately rejects unknown members so schema validation
also enforces its privacy-minimized shape. Missing required members are invalid;
they are never interpreted as zero, empty, or clean.

## Native JSON report

The top-level shape for schema `1.0.0` is:

```json
{
  "schema_version": "1.0.0",
  "tool": {},
  "scan": {},
  "summary": {},
  "findings": [],
  "surfaces": [],
  "errors": []
}
```

All seven members are required, including empty arrays.

### `tool`

| Member | Type | Meaning |
| --- | --- | --- |
| `name` | string | Always `sharelint` for this contract. |
| `version` | string | ShareLint package version that produced the report. |

### `scan`

| Member | Type | Meaning |
| --- | --- | --- |
| `target` | object | Logical input identity; see below. |
| `fingerprint_scope` | string | Random public identifier for this report's ephemeral HMAC key. It is not a key or stable run identity. |
| `limits` | object | Effective finite resource limits used by the run. |

`target` has required `name`, `kind`, and `sha256` members. `name` is a logical
label or basename, not a required absolute path. `kind` describes the filesystem
boundary as `file`, `directory`, or `symlink`; detected container and document
formats appear in the `surfaces` records.
For a regular file, `sha256` hashes its exact bytes. For a directory, it hashes
the scanner's canonical, sorted manifest of selected regular-file paths, sizes,
and content hashes. A directory target hash does not cover skipped special
files; those must be visible as coverage gaps.

`limits` contains the effective values, not merely command-line overrides:

```json
{
  "max_file_bytes": 67108864,
  "max_member_bytes": 33554432,
  "max_total_bytes": 268435456,
  "max_archive_depth": 4,
  "max_archive_members": 10000,
  "max_compression_ratio": 200.0,
  "max_text_chars": 8000000,
  "max_xml_elements": 100000,
  "max_findings": 10000
}
```

Integers are positive JSON integers. `max_compression_ratio` is a finite,
positive JSON number. The semantics of these limits are defined in
[the threat model](threat-model.md#resource-budgets).

### `summary`

| Member | Type | Meaning |
| --- | --- | --- |
| `verdict` | `pass`, `blocked`, or `incomplete` | Policy result with coverage taken into account. |
| `fail_on` | severity string | Lowest finding severity that blocks under the effective policy. |
| `blocking_findings` | integer | Findings at or above `fail_on`. |
| `total_findings` | integer | Length of `findings`. |
| `findings_by_severity` | object | Counts for `info`, `low`, `medium`, `high`, and `critical`; all keys are present. |
| `surface_count` | integer | Length of `surfaces`. |
| `surfaces_by_status` | object | Counts for `scanned`, `partial`, and `skipped`; all keys are present. |
| `bytes_inspected` | integer | Sum of surface bytes inspected. Nested/decompressed bytes may be counted more than once. |
| `error_count` | integer | Length of `errors`. |
| `coverage_complete` | boolean | True only when there are no errors and every required surface is `scanned`. |

Verdict precedence is normative:

1. any error or required `partial`/`skipped` surface makes the verdict
   `incomplete`;
2. otherwise, one or more blocking findings makes it `blocked`;
3. only a complete, non-blocking run is `pass`.

Known, declared capability limits remain visible in `surfaces`. A `pass` means
only "no blocking finding in the completed surfaces under this policy." It is
not a safe-to-share claim.

### `findings`

Each finding has the following required members:

| Member | Type | Meaning |
| --- | --- | --- |
| `rule_id` | string | Stable identifier matching `^SL\.[A-Z][A-Z0-9_]*\.[A-Z][A-Z0-9_]*$`. |
| `severity` | string | `info`, `low`, `medium`, `high`, or `critical`. |
| `title` | string | Short, value-free rule title. |
| `source_chain` | string array | Logical route from the selected root through directories and nested containers. |
| `location` | string | Human-oriented, value-free location label. Consumers MUST treat it as opaque. |
| `masked_preview` | string | Bounded, type-aware mask that never contains the complete matched value. |
| `evidence_fingerprint` | string | Report-scoped correlation token matching `^hmac-sha256:[0-9a-f]{24}$`. |
| `remediation` | string | Generic action that does not repeat the evidence. |
| `tags` | string array | Stable, lowercase classification hints. |

The fingerprint is the first 96 bits of an HMAC-SHA256 result made with a fresh
256-bit key. The key is discarded and never serialized. A fingerprint is
comparable only when both `fingerprint_scope` and `rule_id` match. It MUST NOT
be used for cross-report deduplication, durable suppression, or dictionary
verification. See [Privacy-preserving evidence](threat-model.md#privacy-preserving-evidence).

`source_chain` uses forward-slash logical components and never needs an absolute
root. Archive members extend the array rather than being flattened into an
ambiguous `outer.zip!inner.zip!file` string. Control characters are escaped by
the output renderer. If a rule matched part of a path, that part is masked in
every reported copy of the path. A report-local `[path-ref:pNNNN]` suffix keeps
different raw paths distinguishable when their masked forms collide; it is an
opaque ordinal, may change when the input changes, and is not a durable path ID.

Findings are sorted by descending severity, normalized source chain, location,
and rule ID. Exact duplicates from the same detector and location are coalesced.
Random scopes and fingerprints intentionally differ between otherwise identical
runs.

### `surfaces`

Each entry records a unit of measured coverage:

| Member | Type | Meaning |
| --- | --- | --- |
| `source_chain` | string array | Logical path to the inspected object or container part. |
| `kind` | string | Surface kind, for example `text`, `zip-member`, `ooxml-properties`, `pdf-metadata`, or `image-metadata`. |
| `status` | string | `scanned`, `partial`, or `skipped`. |
| `bytes_inspected` | integer | Actual bytes safely consumed for this surface. |
| `scanner` | string | Stable inspector name, including a version when its behavior changes incompatibly. |
| `note` | string, optional | Privacy-safe coverage explanation. It MUST NOT contain document text or matched evidence. |

`partial` means some work completed but a required part did not. `skipped` means
no meaningful inspection occurred. Either status makes coverage incomplete
unless the surface is an explicitly documented, policy-accepted capability
limit. A producer MUST distinguish that policy acceptance in its note and
receipt; it cannot silently relabel the status `scanned`.

### `errors`

Each error has required `source_chain`, `code`, and `message` members. `code` is
a stable `SL.<CATEGORY>.<RULE>` identifier. `message` is a bounded explanation
that may include a configured limit or safe parser state, but never raw content,
unmasked input paths, decompressed fragments, or exception arguments copied
from an untrusted parser. Any error makes coverage incomplete.

### Example

All values below are synthetic. Repeated hexadecimal characters are only
format examples.

```json
{
  "schema_version": "1.0.0",
  "tool": {
    "name": "sharelint",
    "version": "0.1.0"
  },
  "scan": {
    "target": {
      "name": "review-copy.docx",
      "kind": "file",
      "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    },
    "fingerprint_scope": "9f65c8a4e12b77d0",
    "limits": {
      "max_file_bytes": 67108864,
      "max_member_bytes": 33554432,
      "max_total_bytes": 268435456,
      "max_archive_depth": 4,
      "max_archive_members": 10000,
      "max_compression_ratio": 200.0,
      "max_text_chars": 8000000,
      "max_xml_elements": 100000,
      "max_findings": 10000
    }
  },
  "summary": {
    "verdict": "blocked",
    "fail_on": "high",
    "blocking_findings": 1,
    "total_findings": 1,
    "findings_by_severity": {
      "info": 0,
      "low": 0,
      "medium": 0,
      "high": 1,
      "critical": 0
    },
    "surface_count": 2,
    "surfaces_by_status": {
      "scanned": 2,
      "partial": 0,
      "skipped": 0
    },
    "bytes_inspected": 4096,
    "error_count": 0,
    "coverage_complete": true
  },
  "findings": [
    {
      "rule_id": "SL.OFFICE.COMMENTS",
      "severity": "high",
      "title": "Office comments or review annotations",
      "source_chain": [
        "review-copy.docx",
        "word/comments.xml"
      ],
      "location": "comment 1",
      "masked_preview": "<review-annotation>",
      "evidence_fingerprint": "hmac-sha256:0123456789abcdef01234567",
      "remediation": "Resolve and remove comments in the source application, then export again.",
      "tags": [
        "office",
        "hidden-content"
      ]
    }
  ],
  "surfaces": [
    {
      "source_chain": [
        "review-copy.docx"
      ],
      "kind": "zip-container",
      "status": "scanned",
      "bytes_inspected": 3072,
      "scanner": "zip-v1"
    },
    {
      "source_chain": [
        "review-copy.docx",
        "word/comments.xml"
      ],
      "kind": "ooxml-comments",
      "status": "scanned",
      "bytes_inspected": 1024,
      "scanner": "ooxml-v1"
    }
  ],
  "errors": []
}
```

## SARIF 2.1.0 projection

SARIF output uses `version: "2.1.0"` and the official SARIF 2.1.0 schema URI.
There is one run with `tool.driver.name: "ShareLint"` and
`tool.driver.semanticVersion` equal to the package version. Every referenced
rule appears in `tool.driver.rules` with its ShareLint ID, title, default level,
safe help text, and tags.

### Result mapping

Each native finding becomes one SARIF `result`:

- `ruleId` is the unchanged ShareLint rule ID;
- `message.text` contains only the rule title and masked preview;
- the outermost selected file is represented by a relative, percent-encoded
  `artifactLocation.uri`; absolute local roots are omitted;
- nested `source_chain` components and the opaque native location are preserved
  under `result.properties.sharelint`, because a nested archive member is not a
  physical source file;
- `properties.sharelint.evidenceFingerprint` and
  `properties.sharelint.fingerprintScope` preserve report-local correlation;
- remediation, tags, confidence added by a future minor version, and coverage
  context remain value-free.

ShareLint deliberately does **not** populate SARIF `fingerprints` or
`partialFingerprints`. Those fields are commonly used for durable cross-run
identity, while ShareLint fingerprints are freshly keyed and report-scoped.
Putting them there would cause false deduplication expectations.

Severity maps as follows:

| ShareLint severity | SARIF `level` |
| --- | --- |
| `critical`, `high` | `error` |
| `medium` | `warning` |
| `low`, `info` | `note` |

Coverage errors also become SARIF results with their stable scan/archive rule
ID and `properties.sharelint.coverageError: true`. The full native `surfaces`,
summary, effective limits, target hash, and fingerprint scope are copied under
`run.properties.sharelint`. Consumers deciding whether to publish or merge MUST
use `summary.verdict` and `coverage_complete`; counting SARIF error-level results
alone loses fail-closed coverage semantics.

`invocations[].executionSuccessful` says whether ShareLint itself completed and
serialized a report. Findings do not make tool execution unsuccessful. A
coverage gap is represented separately and cannot be inferred from that SARIF
flag.

## Hash-bound pack receipt

A receipt is a small, privacy-minimized record of a `pack` attempt. There are
two states:

- `packed`: an artifact was committed and the receipt binds its exact bytes,
  per-entry content manifest, native report, and effective policy;
- `blocked`: no artifact was committed. This receipt is written only when the
  caller explicitly supplied `--receipt`; it binds the aggregate result and
  native report without copying finding details.

A blocked pack writes no receipt by default. No receipt state other than
`packed` is evidence that an artifact was produced.

Whenever `pack` emits a receipt, it also writes the exact native companion
report whose bytes are bound by `report_sha256`. The default successful names
are `OUTPUT.sharelint.json` and `OUTPUT.sharelint.report.json`; an explicit
`--receipt attempt.json` uses `attempt.report.json` unless `--report` selects a
different path. The companion report contains masked findings and contextual
filenames and SHOULD be protected as a sensitive record.

All receipts MUST omit finding objects, `masked_preview`,
`evidence_fingerprint`, `fingerprint_scope`, finding locations, source chains,
detector/parser messages, remediation, and raw exception text. A successful
receipt does list ZIP member paths, sizes, and hashes because those paths are
already observable in the artifact. A blocked receipt MUST NOT contain that
file list.

### Common members

Schema `1.0.0` requires these members in both states:

| Member | Type | Meaning |
| --- | --- | --- |
| `schema_version` | string | Receipt schema, currently `1.0.0`. |
| `receipt_type` | string | Always `sharelint.pack`. |
| `status` | `packed` or `blocked` | Whether an artifact was committed. |
| `tool` | object | ShareLint name and version. |
| `created_at` | string | Self-asserted RFC 3339 UTC timestamp. |
| `source` | object | Safe target kind and source digest status; no absolute path. |
| `policy` | object | Effective threshold, limits, policy hash, and ruleset hash. |
| `summary` | object | Aggregate native summary; no finding array. |
| `report_sha256` | string | SHA-256 of the exact native report bytes. |
| `reasons` | string array | Empty for `packed`; one or more generic reason codes for `blocked`. |
| `claim` | string | Human-readable, non-normative scope statement; consumers MUST use structured members for decisions. |

`source` contains `kind`, `hash_status` (`complete` or `unavailable`), and a
`sha256` member only when the hash is complete. A blocked receipt may say the
source hash was unavailable; it MUST NOT substitute a partial digest and call
it complete.

`policy` contains `sha256`, `ruleset_sha256`, `fail_on`,
`require_complete_coverage` (always `true`), and the same effective `limits`
object as the native report. `summary` copies only aggregate fields from the
native summary. It does not embed or paraphrase any finding.

Stable blocked reason codes are:

- `blocking_findings`;
- `coverage_incomplete`;
- `source_changed`;
- `pack_write_failed`;
- `artifact_rescan_failed`;
- `artifact_manifest_mismatch`.

More than one may apply. They are safe machine codes, not free-form error
messages. An unsupported reason is handled conservatively by verifiers.

### Successful receipt

A `packed` receipt additionally requires `archive`, `files`, and
`verification`. For example:

```json
{
  "schema_version": "1.0.0",
  "receipt_type": "sharelint.pack",
  "status": "packed",
  "tool": {
    "name": "sharelint",
    "version": "0.1.0"
  },
  "created_at": "2030-01-01T00:00:00Z",
  "source": {
    "kind": "directory",
    "hash_status": "complete",
    "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  },
  "policy": {
    "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "ruleset_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    "fail_on": "high",
    "require_complete_coverage": true,
    "limits": {
      "max_file_bytes": 67108864,
      "max_member_bytes": 33554432,
      "max_total_bytes": 268435456,
      "max_archive_depth": 4,
      "max_archive_members": 10000,
      "max_compression_ratio": 200.0,
      "max_text_chars": 8000000,
      "max_xml_elements": 100000,
      "max_findings": 10000
    }
  },
  "summary": {
    "verdict": "pass",
    "fail_on": "high",
    "blocking_findings": 0,
    "total_findings": 0,
    "findings_by_severity": {
      "info": 0,
      "low": 0,
      "medium": 0,
      "high": 0,
      "critical": 0
    },
    "surface_count": 2,
    "surfaces_by_status": {
      "scanned": 2,
      "partial": 0,
      "skipped": 0
    },
    "bytes_inspected": 4096,
    "coverage_complete": true,
    "error_count": 0
  },
  "report_sha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
  "reasons": [],
  "claim": "0 policy-blocking findings across 2 surface records; this receipt is not a guarantee that the archive contains no sensitive data",
  "archive": {
    "format": "zip",
    "size": 12345,
    "sha256": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
    "profile": "deterministic-zip-v1"
  },
  "files": [
    {
      "path": "nested/a-first.txt",
      "size": 19,
      "sha256": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    },
    {
      "path": "z-last.txt",
      "size": 19,
      "sha256": "1111111111111111111111111111111111111111111111111111111111111111"
    }
  ],
  "verification": {
    "coverage_complete": true,
    "reopened_and_rescanned": true,
    "manifest_matched": true
  }
}
```

`files` is sorted by normalized POSIX member path. Every item has exactly
`path`, `size`, and `sha256`. Paths are relative, contain no empty, `.` or `..`
component, use `/`, and are the names present in the final ZIP. Duplicate paths
are invalid. `size` is the exact uncompressed byte count and `sha256` hashes the
exact uncompressed member bytes.

The list reveals bundle filenames and should be protected with the artifact. It
MUST describe regular files only; directories are implicit and links/special
files cannot appear in a successful pack.

### Blocked-attempt receipt

When and only when `--receipt` was explicitly requested, a blocked pack writes a
record like this and writes no archive:

```json
{
  "schema_version": "1.0.0",
  "receipt_type": "sharelint.pack",
  "status": "blocked",
  "tool": {
    "name": "sharelint",
    "version": "0.1.0"
  },
  "created_at": "2030-01-01T00:00:00Z",
  "source": {
    "kind": "directory",
    "hash_status": "complete",
    "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  },
  "policy": {
    "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "ruleset_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    "fail_on": "high",
    "require_complete_coverage": true,
    "limits": {
      "max_file_bytes": 67108864,
      "max_member_bytes": 33554432,
      "max_total_bytes": 268435456,
      "max_archive_depth": 4,
      "max_archive_members": 10000,
      "max_compression_ratio": 200.0,
      "max_text_chars": 8000000,
      "max_xml_elements": 100000,
      "max_findings": 10000
    }
  },
  "summary": {
    "verdict": "blocked",
    "fail_on": "high",
    "blocking_findings": 2,
    "total_findings": 2,
    "findings_by_severity": {
      "info": 0,
      "low": 0,
      "medium": 0,
      "high": 1,
      "critical": 1
    },
    "surface_count": 1,
    "surfaces_by_status": {
      "scanned": 1,
      "partial": 0,
      "skipped": 0
    },
    "bytes_inspected": 2048,
    "coverage_complete": true,
    "error_count": 0
  },
  "report_sha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
  "reasons": [
    "blocking_findings"
  ],
  "claim": "No archive was created because the ShareLint pack policy did not pass"
}
```

`archive`, `files`, and `verification` MUST be absent when `status` is
`blocked`. The receipt contains neither the blocking rule IDs nor any finding
content; the separately protected native report is the only detailed record.
If coverage, rather than severity, blocked the attempt, `summary.verdict` is
`incomplete` and `reasons` includes `coverage_incomplete`.

### Receipt digest semantics

- `archive.sha256` hashes every byte of the final, closed archive. Under the
  same `deterministic-zip-v1` profile, the same logical paths and file contents
  may reproduce the same archive bytes and digest; any byte-level difference
  changes the digest.
- each `files[].sha256` hashes exact uncompressed member bytes; the ordered
  path/size/hash list is the content-addressed manifest checked after reopening;
- `report_sha256` hashes the exact bytes of the native report associated with
  the attempt, including its final newline if present;
- `policy.sha256` hashes the canonical effective policy after defaults and
  overrides are resolved;
- `policy.ruleset_sha256` hashes a canonical descriptor with
  `format: "sharelint-ruleset-v1"`, `engine: "builtin-v1"`, and `rules` sorted
  by rule `id`. Each rule object contains exactly `id`, `title`, `severity`,
  `remediation`, and lexicographically sorted `tags`.

ShareLint canonical JSON v1 is UTF-8, has object keys sorted by Unicode code
point, no insignificant whitespace, JSON-standard escaping, array order
preserved, finite numbers only, and no trailing newline. Internal manifest,
policy and ruleset digests use those canonical bytes. Digests of emitted archive
and report files always use their exact bytes instead.

The receipt itself contains no self-referential digest. Its exact bytes may be
hashed or signed by an external tool. Receipt verification MUST distinguish:

- **schema valid**: required fields and constraints are present;
- **artifact match**: for `packed`, the supplied artifact's exact SHA-256 and
  size match and its reopened entries match `files`;
- **report match**: the supplied report's exact SHA-256 matches;
- **fully matched**: for `packed`, schema, artifact, manifest, and report all
  match.

If a report was not supplied, verification cannot be "fully matched." A
`blocked` receipt has no artifact to match and MUST always be presented as a
blocked attempt, never as a partially verified pack. A hash match does not mean
detectors were rerun during verification.

### Receipt security meaning

Changing a packed artifact or member, report, policy descriptor, ruleset
descriptor, or recorded limit breaks its corresponding binding. The receipt
therefore makes accidental substitution and stale evidence detectable when the
referenced objects are available. A blocked receipt binds only its source state,
policy, aggregate outcome, reason codes, and report; by construction it cannot
authorize an artifact.

The receipt is not signed. Anyone able to replace an artifact can create a new
receipt and report, and timestamps are self-asserted. A fully matched packed
receipt means "these bytes match this receipt," not "a trusted person created
them" or "the artifact contains no sensitive data." See the
[fail-closed pack contract](threat-model.md#fail-closed-pack) for the conditions
under which ShareLint may issue the receipt.
