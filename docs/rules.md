# Rules and identifiers

ShareLint rules are deterministic, local checks. A rule reports evidence that
deserves review; absence of a finding is not proof that the corresponding data
does not exist.

Rule identifiers, default severities, and privacy behavior are public
compatibility contracts. The installed release's rule registry is authoritative
for which rules it can actually run.

## Identifier grammar

Built-in IDs have exactly three dot-separated ASCII components:

```text
SL.<CATEGORY>.<RULE>
```

They are case-sensitive and match:

```text
^SL\.[A-Z][A-Z0-9_]*\.[A-Z][A-Z0-9_]*$
```

- `SL` is reserved for rules shipped by ShareLint.
- `CATEGORY` names the inspected privacy or safety surface.
- `RULE` names the stable condition, not the current regular expression or
  implementation technique.

IDs do not contain a severity, format version, scanner implementation, or year.
For example, `SL.SECRET.AWS_ACCESS_KEY` remains valid if its detector is refined
or its default severity changes. A materially different meaning receives a new
ID.

The current categories are:

| Category | Scope |
| --- | --- |
| `SECRET` | Credentials, tokens, keys, and likely credential assignments |
| `PII` | Structured personal identifiers in content |
| `PATH` | Identity or confidential context exposed by a path or filename |
| `ARCHIVE` | Container traversal, encryption, links, and safety limits |
| `OFFICE` | OOXML metadata, hidden/review content, relationships, and active content |
| `PDF` | PDF metadata, attachments, history, encryption, and active content |
| `IMAGE` | Image metadata and embedded metadata surfaces |
| `SCAN` | Coverage or inspection failures not specific to one format |

New categories require a documented security meaning. Third-party tools MUST
NOT mint `SL.*` IDs. ShareLint 0.1 has no runtime plugin rule namespace; a future
extension contract will define one rather than letting custom rules masquerade
as built-ins.

## Stability policy

Within a schema major version:

- an ID is never reused for a different condition;
- a detector may reduce false positives or add equivalent encodings while
  retaining its ID;
- a detector expansion to a new semantic data class uses a new ID;
- a retired rule remains reserved and is marked deprecated before removal;
- a replacement is documented explicitly; reports are never silently rewritten
  from an old ID to a new one;
- consumers key policy on `rule_id`, never on localized title, message, tag, or
  severity.

The ruleset descriptor is a canonical JSON object with
`format: "sharelint-ruleset-v1"`, `engine: "builtin-v1"`, and a `rules` array
sorted by rule `id`. Each rule object contains exactly `id`, `title`,
`severity`, `remediation`, and lexicographically sorted `tags`.
`ruleset_sha256` hashes those canonical bytes. The current descriptor does not
claim to bind detector implementation versions or detector options.

## Severity and blocking

Severities describe likely disclosure impact, not detector certainty:

| Severity | Intended meaning |
| --- | --- |
| `critical` | Credential/private-key exposure or executable/active content with severe impact |
| `high` | Direct sensitive-data exposure, hidden content, unsafe container behavior, or a required coverage failure |
| `medium` | Personal or organizational metadata that normally needs contextual review |
| `low` | Weak contextual disclosure or low-impact metadata |
| `info` | Coverage/capability information that still needs to remain visible |

The default policy blocks at `high`: `high` and `critical` findings block, while
lower severities remain reviewable. Policy can change the threshold, but the
effective value is recorded in the report and receipt.

Coverage is a separate axis. An encrypted member, parser/read error, exhausted
budget, or required unsupported surface makes the result incomplete and blocks
`pack` even if its informational rule severity is below `fail_on`. A producer
MUST NOT turn a coverage gap into `pass` by lowering its severity.

## Detection and evidence contract

Every detector MUST:

1. operate only on bounded bytes or decoded text supplied by an inspector;
2. produce a registered rule ID and generic, value-free title/remediation;
3. send the matched value directly to the report-scoped `EvidenceProtector`;
4. retain only a type-aware `masked_preview` and `evidence_fingerprint` in the
   finding, then discard the raw capture;
5. keep exception text, parser notes, tracing, and debug output free of the raw
   value;
6. report the logical source chain and a bounded, safe location;
7. have synthetic positive, negative, masking, malformed-input, and boundary
   tests appropriate to its risk.

The current fingerprint binds `rule_id` and evidence. Two equal values found by
the same rule in one report therefore have the same fingerprint; the same value
under different rules or in different reports does not. Fingerprints are not
stable suppression keys. See [the report contract](report-format.md#findings).

Specialized credential rules take precedence over
`SL.SECRET.GENERIC_ASSIGNMENT` for the same character span. The same
`rule_id`/source-chain/location/evidence tuple is emitted once. Findings are
sorted deterministically after detection; HMAC fingerprints and their scope are
intentionally fresh for each report.

Text pattern matches are syntactic and bounded. Metadata and structural rules
report the presence of a risky surface; they do not interpret intent. A parser
that cannot establish the precondition for a rule records coverage as partial
or skipped instead of assuming the rule did not match.

## Built-in rule catalog

The following IDs and defaults define the ShareLint 0.1 baseline. The exact
encodings and supported format variants for an installed release are exposed by
that release's rule/scanner listing and measured surface report.

### Secrets

| ID | Default | Condition |
| --- | --- | --- |
| `SL.SECRET.PRIVATE_KEY` | critical | Recognized private-key material or container marker |
| `SL.SECRET.AWS_ACCESS_KEY` | critical | AWS access-key identifier syntax |
| `SL.SECRET.GITHUB_TOKEN` | critical | Recognized GitHub token prefix and shape |
| `SL.SECRET.JWT` | critical | Three-part JSON Web Token syntax; validity and revocation are not tested |
| `SL.SECRET.GENERIC_ASSIGNMENT` | high | A credential-like key name assigned a non-placeholder value |

Secret detectors use credential-shaped context and bounded length checks to
avoid treating every high-entropy string as a credential. They cannot determine
whether a credential is live. A match should be removed and, when potentially
real, rotated or revoked outside ShareLint.

### Personal information

| ID | Default | Condition |
| --- | --- | --- |
| `SL.PII.EMAIL` | medium | Syntactically plausible email address |
| `SL.PII.US_SSN` | high | US Social Security number pattern after structural exclusions |
| `SL.PII.PAYMENT_CARD` | high | Plausible payment-card digits passing structural/checksum validation |

These are pattern findings, not proof of identity, ownership, geography, or
validity. Region-specific identifiers require separate, explicit rules; they
must not be folded into a broad generic ID with an unknowable false-positive
rate.

### Paths

| ID | Default | Condition |
| --- | --- | --- |
| `SL.PATH.LOCAL_HOME` | medium | Platform-shaped absolute home-directory path in content or metadata |
| `SL.PATH.EMAIL_IN_NAME` | high | Email syntax in a file, directory, or archive-member name |
| `SL.PATH.SENSITIVE_LABEL` | low | A configured sensitive-context label in a path component |

Path matching is performed on logical paths before display escaping. If the
path itself is evidence, every report representation masks the matched
component. Report-local opaque path references keep masked collisions distinct.
Archive path safety is covered by `SL.ARCHIVE.*`, not these privacy rules.

### Archives

| ID | Default | Condition |
| --- | --- | --- |
| `SL.ARCHIVE.PATH_TRAVERSAL` | critical | Absolute, drive-qualified, NUL-containing, or boundary-escaping member path |
| `SL.ARCHIVE.SYMLINK` | high | A symbolic-link entry or link crossing the selected share boundary |
| `SL.ARCHIVE.DUPLICATE_PATH` | high | Two entries resolve to the same normalized archive path |
| `SL.ARCHIVE.ENCRYPTED_MEMBER` | high | A member that cannot be inspected without decryption |
| `SL.ARCHIVE.LIMIT_EXCEEDED` | high | Depth, member, expanded-byte, per-member, text, XML-element, or compression-ratio budget exceeded |

Archive safety rules are both findings and coverage controls. They apply to ZIP
and OOXML packages and to nested containers. A declared uncompressed size is
not trusted: actual bytes streamed are counted. Archive inspection never writes
members to disk. Archive and entry comments are scanned as bounded text;
extra-field framing is inspected, and an unknown extra-field type is a coverage
gap even when its raw bytes were submitted to text rules.

`SL.ARCHIVE.LIMIT_EXCEEDED` deliberately has one stable ID across budget axes;
the privacy-safe error message names the effective limit that stopped the scan.
Consumers must use coverage state to gate `pack`, not parse English messages to
decide whether the run was complete.

### Office Open XML

| ID | Default | Condition |
| --- | --- | --- |
| `SL.OFFICE.AUTHOR_METADATA` | medium | Creator or last-modified-by metadata |
| `SL.OFFICE.ORGANIZATION_METADATA` | medium | Company, manager, or organization metadata |
| `SL.OFFICE.CUSTOM_PROPERTIES` | medium | Custom document properties |
| `SL.OFFICE.COMMENTS` | high | Comments or review annotations |
| `SL.OFFICE.TRACKED_CHANGES` | high | Tracked, inserted, or deleted revision content/history |
| `SL.OFFICE.HIDDEN_TEXT` | high | Hidden Word text |
| `SL.OFFICE.HIDDEN_SHEET` | high | Hidden spreadsheet sheet |
| `SL.OFFICE.NOTES` | high | Presentation speaker notes |
| `SL.OFFICE.HIDDEN_SLIDE` | high | Hidden presentation slide |
| `SL.OFFICE.EXTERNAL_RELATIONSHIP` | high | Relationship to an external file or URL |
| `SL.OFFICE.EMBEDDED_OBJECT` | high | Embedded package or object needing its own inspection |
| `SL.OFFICE.MACRO` | critical | Macro project or macro-enabled active content |
| `SL.OFFICE.CUSTOM_XML` | medium | Custom XML payload outside recognized document parts |
| `SL.OFFICE.THUMBNAIL` | low | Package preview thumbnail that may expose an earlier state |
| `SL.OFFICE.PRINTER_SETTINGS` | low | Cached printer settings that may identify a device or organization |

OOXML is inspected as a ZIP package first. Missing required parts, ambiguous
relationships, unsupported compression, malformed XML, and embedded content
that cannot be recursively inspected are coverage gaps, never implicit
non-matches. XML parts are parsed as streams under a per-part element limit;
completed trees are not retained. ShareLint does not run Office or VBA.

### PDF

| ID | Default | Condition |
| --- | --- | --- |
| `SL.PDF.AUTHOR_METADATA` | medium | Author or identity-bearing Info/XMP metadata |
| `SL.PDF.SOFTWARE_METADATA` | low | Creator, producer, or software metadata |
| `SL.PDF.ACTIVE_CONTENT` | critical | JavaScript, launch/open actions, rich media, or related active behavior |
| `SL.PDF.EMBEDDED_FILE` | high | Embedded file or attachment |
| `SL.PDF.ENCRYPTED` | high | Password-protected/encrypted content that cannot be fully inspected |
| `SL.PDF.INCREMENTAL_HISTORY` | medium | Incremental revisions that may retain earlier document state |

PDF checks are static and limited to structures understood by the installed
scanner. They do not render pages. Unsupported filters, corrupt object graphs,
truncation, or undecodable required streams become coverage errors.

### Images

| ID | Default | Condition |
| --- | --- | --- |
| `SL.IMAGE.GPS_METADATA` | high | GPS or precise location metadata |
| `SL.IMAGE.IDENTITY_METADATA` | medium | Artist, copyright, owner, author, or similar identity metadata |
| `SL.IMAGE.DEVICE_METADATA` | low | Camera, phone, lens, serial, or software metadata |
| `SL.IMAGE.TEXT_METADATA` | medium | Free-form image description, comment, or XMP text metadata |

Baseline image rules inspect recognized metadata, embedded metadata, and
preview structures within limits. They do not claim to inspect text visible in
pixels. OCR, if added later, is a separately named scanner surface and its
availability and status must be recorded.

### Scan and coverage

| ID | Default | Condition |
| --- | --- | --- |
| `SL.SCAN.UNSUPPORTED_CONTENT` | info | A detected content surface has no applicable complete inspector |
| `SL.SCAN.READ_ERROR` | high | Bytes or required parser state could not be inspected safely |

These IDs often accompany a `partial` or `skipped` surface and/or a native
report error. Their coverage effect takes precedence over default severity.
Examples include permission errors, malformed/truncated structures, unsupported
encodings or compression methods, file changes during inspection, and special
filesystem objects. Error messages describe the class of failure without
copying raw exception data from untrusted content.

## Policy overrides and suppressions

Any severity override, disabled rule, path exclusion, accepted capability gap,
or changed threshold is part of the effective policy. `pack` binds the
canonical effective policy and ruleset hashes in its receipt.

Suppressions SHOULD be narrow: a rule ID, a bounded logical path selector, an
explicit reason, and optional expiry. They MUST NOT use
`evidence_fingerprint`, because that value intentionally changes every report.
A suppressed or disabled rule is not reported as scanned coverage for the
surface it would have inspected, and the receipt must not imply otherwise.

## Adding or changing a rule

A rule change is complete only when it includes:

- a grammar-valid, semantically stable ID and safe title/remediation;
- default severity and tags justified by disclosure impact;
- documented applicable formats and known blind spots;
- deterministic positive and negative fixtures containing only synthetic data;
- false-positive, malformed-input, size-boundary, masking, fingerprint-scope,
  and nested-provenance tests where applicable;
- confirmation that terminal, JSON, SARIF, errors, and receipts never expose
  raw evidence;
- an explicit detector-version or ruleset change so old receipts cannot claim
  the new behavior.

Changing a regular expression without reviewing masking, resource use,
catastrophic backtracking, Unicode behavior, overlap precedence, and report
output is a security-relevant change.
