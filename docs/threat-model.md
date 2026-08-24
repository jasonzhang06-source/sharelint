# Threat model

This document defines the security boundary for the ShareLint 0.1 Alpha line. The words
**MUST**, **MUST NOT**, **SHOULD**, and **MAY** describe requirements for the
scanner, reporters, and `pack` workflow.

ShareLint is a zero-runtime-dependency, local privacy preflight tool. It helps a
person find likely disclosure risks before sharing a directory or file. It is
designed to inspect hostile input without executing it and to say explicitly
when inspection was incomplete.

## Security objectives

ShareLint has five primary objectives:

1. **Keep input local.** Scanned bytes, filenames, findings, and telemetry MUST
   NOT be sent over a network by default. The core scan path has no network
   feature.
2. **Do not echo evidence.** Raw matched values MUST NOT appear in normal
   terminal output, machine reports, exceptions, debug logs, temporary files,
   or receipts.
3. **Bound attacker-controlled work.** Directory traversal, archive nesting,
   member counts, decompression, and parser input MUST have finite limits that
   are enforced while data is streamed, not only from untrusted size headers.
4. **Make coverage honest.** An unreadable, encrypted, malformed, truncated,
   unsupported, skipped, or budget-limited surface MUST be represented as a
   coverage gap. It MUST NOT produce a clean verdict by omission.
5. **Bind successful exports to what was checked.** `pack` MUST only publish an
   artifact after all required checks complete, then bind the exact artifact,
   report, policy, tool version, limits, and measured coverage in a receipt.

## Trust boundary and assumptions

The trusted computing base is the installed ShareLint release, the Python
standard library and interpreter, the operating system, and the policy and
command line selected by the local operator. Release verification and host
hardening are outside ShareLint itself.

All scanned material is untrusted, including:

- file and directory names, symlinks, special files, permissions, and metadata;
- ZIP and Office Open XML headers, paths, comments, extra fields, compression
  metadata, and nested members;
- PDF objects, streams, cross-reference data, incremental revisions, actions,
  and attachments;
- image dimensions, chunks, EXIF/XMP/IPTC metadata, profiles, thumbnails, and
  embedded previews;
- encodings, control characters, bidirectional text, very long lines, duplicate
  names, and values intended to trigger or confuse a detector.

The operator is assumed to control the input and output locations and to keep
the local report appropriately private. A compromised host, interpreter,
ShareLint binary, or operator can read the original input and can forge output.

## Data flow

The intended data flow is local and one-way:

```text
untrusted paths and bytes
        |
        v
bounded traversal -> format inspectors -> deterministic rules
        |                  |                    |
        +---------- coverage/errors ------------+
                           |
                           v
                  privacy-safe report
                           |
                  strict pack gate only
                           v
             reopened artifact + receipt hashes
```

Format inspectors MUST NOT execute macros, JavaScript, launch actions, shell
commands, embedded programs, or external relationships. They MUST NOT render a
document in an office suite, browser, PDF viewer, or image application. An
archive MUST be inspected through bounded streams and MUST NOT be extracted to
the filesystem.

## Threats and required controls

| Threat | Required control | Residual risk |
| --- | --- | --- |
| A secret or low-entropy PII value leaks through output | Mask previews and use a fresh report-scoped keyed fingerprint; never serialize the key or raw match | Masks, lengths, locations, counts, and surrounding filenames can still be identifying |
| An attacker dictionary-attacks a published value hash | Use HMAC-SHA256 with a fresh 256-bit random key per report; discard the key after the run | A process or memory compromise during the scan can obtain the key or original value |
| Filenames or metadata inject terminal control sequences | Escape control and bidirectional characters in human output; JSON-encode machine output; never interpret report text as markup | A downstream consumer that renders untrusted fields unsafely can reintroduce the issue |
| A ZIP member escapes the scan root | Reject absolute, drive-qualified, NUL-containing, and `..`-escaping member paths after separator normalization; never extract | Unicode-confusable names may still mislead a human reviewer |
| A ZIP bomb consumes memory, disk, or CPU | Enforce depth, member, per-file, compression-ratio, text, and total expanded-byte budgets before and during streaming | Finite work can still be expensive up to the configured limits |
| Size headers lie or a stream expands after a precheck | Treat headers as hints and count actual bytes read; stop immediately when a runtime counter crosses a limit | Parser and standard-library defects remain possible |
| A nested archive evades extension-based detection | Prefer validated magic/container structure over suffix alone and apply the same recursive budgets to nested ZIP/OOXML content | Unsupported or deliberately ambiguous formats remain coverage gaps |
| A PDF, image, or OOXML parser reaches active content | Inspect bytes as data only; do not resolve external references or execute/render active content | Static inspection cannot model every viewer or application behavior |
| A symlink, Windows reparse point, device, FIFO, or socket reaches outside the selected boundary | Do not follow directory links or reparse points; do not pack special files; report the skipped surface | A platform-specific filesystem race may still be possible |
| Hidden metadata survives in a Windows alternate data stream, Linux/macOS extended attribute, or macOS resource fork | Enumerate only enough to establish presence without reporting names or values; treat presence or probe failure as incomplete coverage and block `pack` | Hidden values are deliberately not classified; filesystem races and privileged kernel behavior remain outside the boundary |
| The source changes while it is being scanned or packed | Hash the exact byte stream that is inspected and packed, check identity/size changes, and fail on a mismatch; reopen and rescan the completed artifact | A malicious kernel, filesystem, or privileged process is outside the boundary |
| A partial scan is presented as clean | Keep findings separate from coverage; errors, limits, encryption, and required unsupported surfaces force an incomplete result | A supported detector can still have false negatives |
| A failed export leaves a misleading artifact | Build in a private temporary file, publish only after all checks pass, and remove partial output on best effort; a requested blocked-attempt receipt is clearly marked and has no artifact fields | Crashes can leave an identifiable temporary file; callers should protect the output directory |
| A receipt is copied to another artifact | Bind exact artifact and report bytes with SHA-256 and include the effective policy, ruleset, limits, and coverage summary | An unsigned receipt does not identify its creator and can be replaced together with the artifact |

## Resource budgets

Every scan MUST use finite, positive effective limits. The report and receipt
record the values actually used. Implementations may lower work before a limit
when continuing would be unsafe, but MUST NOT silently raise a limit.

The baseline limit set is:

- `max_file_bytes`: maximum bytes read from a top-level regular file;
- `max_member_bytes`: maximum expanded bytes read from one archive member;
- `max_total_bytes`: cumulative bytes inspected after decompression across the
  complete top-level target;
- `max_archive_depth`: maximum open archive nesting; a top-level ZIP or OOXML
  package has depth 1 and each nested archive increments it;
- `max_archive_members`: cumulative members encountered across all archives in
  the top-level target, including directories and members later rejected; the
  same numeric ceiling also bounds filesystem entries enumerated for a directory
  target before traversal is marked incomplete;
- `max_compression_ratio`: expanded bytes divided by compressed bytes, enforced
  for each member and for an archive in aggregate; a non-empty member declaring
  zero compressed bytes is treated as exceeding the ratio;
- `max_text_chars`: maximum decoded characters submitted to text detectors;
- `max_xml_elements`: maximum XML elements parsed from one OOXML package part;
- `max_findings`: maximum retained finding objects for the complete top-level
  scan. Reaching it stops further finding collection and creates an explicit
  coverage gap; it never truncates silently into a clean verdict.

Duplicate members and content reached through different container chains count
again. OOXML packages consume the same ZIP budgets as ordinary archives.
Counters use actual streamed bytes. Overflow, negative metadata, impossible
sizes, and inconsistent end-of-stream values are parser errors.

Crossing a limit stops inspection of the affected surface, records
`SL.ARCHIVE.LIMIT_EXCEEDED` or an appropriate scan error, marks coverage as
partial/skipped, and makes the run incomplete. `scan` may still report findings
from work completed safely; `pack` MUST fail and MUST NOT publish an artifact or
`status: "packed"` receipt. By default a blocked pack writes neither a receipt
nor a report. If the caller explicitly supplied `--receipt`, ShareLint writes a
privacy-minimized `status: "blocked"` attempt receipt plus the exact,
separately protected native companion report bound by that receipt.

## Format coverage

Coverage is reported per source chain and format surface. "Scanned" means the
documented inspector completed within its declared capability; it does not mean
that every human-visible or application-specific representation was understood.

- **Directories:** regular files are inspected recursively in stable order.
  Symlinks are not followed by default, and special files are not read. On
  Linux and macOS, regular files and directories receive a presence-only
  extended-attribute probe. On Windows, they receive a presence-only alternate
  data-stream probe. The probes do not expose hidden names or values; present
  metadata and probe failures are explicit coverage gaps.
- **ZIP and OOXML:** members are inspected as bounded streams; archive and entry
  comments are submitted to text rules, and extra fields are framed and scanned.
  Unknown extra-field types remain explicit gaps. OOXML inspectors examine
  recognized package parts and relationships. Encryption, corruption, unsafe
  paths, and unsupported compression methods are explicit gaps.
- **PDF:** static inspection covers the PDF structures documented by the
  installed release. Password protection, undecodable streams, malformed object
  graphs, or unsupported filters are explicit gaps; no viewer is invoked.
- **Images:** recognized metadata and embedded metadata/preview surfaces are
  inspected within limits. Image pixels are not OCR-scanned unless a separately
  reported local OCR capability is enabled. "Metadata scanned" MUST NOT be
  rendered as "all image content scanned."

Known capability limits are listed in the report even when the active policy
allows them. Operational failures are never downgraded to known capability
limits.

## Privacy-preserving evidence

Each report creates a fresh 256-bit key from the operating system CSPRNG and a
random public `fingerprint_scope`. For the current contract, a finding's
fingerprint is:

```text
"hmac-sha256:" + first_24_lower_hex(
    HMAC-SHA256(key, UTF8(rule_id + NUL + detector_evidence))
)
```

The key MUST NOT be written to a report, receipt, cache, log, environment
variable, or command line. It is released after the report is complete. Python
cannot guarantee physical zeroization of immutable objects, so this is key
discard, not a secure-memory claim.

An `evidence_fingerprint` is only a correlation hint for duplicate evidence
under the same `rule_id` and `fingerprint_scope`. It is not an evidence hash,
identity, durable suppression key, cross-run identifier, or proof that two
different values cannot collide. Consumers MUST NOT compare fingerprints from
different scopes. Receipt files contain aggregate counts and a report digest,
but never finding previews, fingerprints, locations, or messages. A successful
receipt may list the paths, sizes, and hashes of files that are already visible
inside its ZIP artifact. A blocked receipt has no file manifest.

Masking is type-aware and bounded. Credentials and private keys reveal only a
type and bounded length; national/payment identifiers reveal only a digit
count; email previews hide the local part and domain body. A complete match is
never shown. If the evidence occurs in a path, the matched path component is
masked before that path is displayed. Report-local opaque path references
distinguish different paths whose masks collide without restoring the raw
component. Absolute input roots are not required in machine reports.

Reports remain sensitive despite these controls: paths, document structure,
rule types, counts, and masked shapes may reveal context. Report files SHOULD be
created with owner-only permissions where the platform supports them.
CLI report and demo outputs MUST use atomic, non-overwriting publication. A scan
report MUST NOT be written over its input or inside a directory being scanned.

## Fail-closed `pack`

`pack` is stricter than `scan`. A successful pack requires all of the following:

1. every selected entry is a regular, bounded input and the exact bytes written
   to the bundle are the bytes inspected;
2. no finding meets the effective blocking threshold;
3. no required surface is partial or skipped, no parser/IO error occurred, and
   no budget was exhausted;
4. the completed archive is closed, reopened as untrusted input, and rescanned
   under the same effective policy and limits;
5. the reopened result is complete and non-blocking, and its content manifest
   matches the pre-pack manifest;
6. SHA-256 digests are computed over the final artifact bytes and exact report
   bytes before a receipt is emitted.

The artifact, exact native companion report, and `status: "packed"` receipt are
published only after these conditions hold. Existing output is not silently
treated as verified, and a leftover partial file has no evidentiary status.

If `pack` is blocked, the default is to write neither artifact, receipt, nor
report. An explicit `--receipt PATH` requests a privacy-minimized audit receipt
and its exact native companion report for the attempt. The receipt MUST have
`status: "blocked"` and contain only a safe source identity, effective policy,
aggregate summary, report SHA-256, and generic reason codes. It MUST NOT contain
an artifact/archive digest, file manifest, findings, masks, fingerprints,
locations, source chains, parser messages, or raw exception text. The companion
report does contain masked findings and contextual source chains and MUST be
protected accordingly. The presence of a blocked receipt can never be
interpreted as a successful export.

The receipt proves only that particular bytes were associated with a particular
ShareLint result and configuration. Receipt verification recomputes hashes and
schema constraints; it does not rerun detectors unless explicitly requested.

## Non-promises and out-of-scope threats

ShareLint does **not** promise or provide:

- proof that an artifact is anonymous, safe, harmless, or free of all sensitive
  information;
- legal, contractual, regulatory, privacy, export-control, or compliance
  certification;
- malware detection, sandboxing, file-format repair, password cracking, or
  analysis of application-specific rendering behavior;
- OCR of image pixels in the dependency-free baseline, semantic understanding
  of prose, or recognition of every regional identifier and secret format;
- automatic irreversible sanitization of originals; scanners preserve source
  files and findings are review prompts;
- authenticity, signer identity, non-repudiation, timestamp authority, or
  transparency-log inclusion for an unsigned receipt;
- protection when the local host, runtime, scanner, policy, output directory,
  or release artifact is compromised;
- zero false positives or zero false negatives.

Accordingly, user-visible conclusions use language such as "no blocking
findings in the inspected surfaces under this policy" rather than "safe to
share."
