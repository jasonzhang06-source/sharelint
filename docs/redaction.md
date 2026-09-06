# Reviewable text derivatives

ShareLint 3.0 adds a deliberate write workflow for a **new UTF-8 text file**.
Scanning still never changes originals. Redaction does not edit source files,
clean document containers, execute input, upload content, or send a handoff.

```bash
sharelint redact plan private.log --name public.log -o redaction.plan.json
sharelint redact inspect redaction.plan.json
sharelint redact apply private.log --plan redaction.plan.json -o public.log
sharelint redact verify public.log --plan redaction.plan.json --receipt public.log.sharelint-redact.json --report public.log.sharelint-redact.report.json
```

The plan step does not create a derivative. Inspect the proposed positions and
rules, then explicitly apply it. Keep the intended filename supplied with
`--name`: the final output basename must match it. A destination directory can
change; the bound basename cannot. Defaults use `redacted.txt`.

## Supported transformations

Matched spans for email, US SSN, payment-card, local-home-path, AWS access-key,
GitHub-token, JWT, and generic credential-assignment rules can be replaced with
the fixed literal `[REDACTED]`. Source offsets are zero-based Unicode codepoint
positions with an exclusive end; line numbers are one-based. Overlapping spans
are merged, and long GitHub/generic-token tails are removed rather than leaving
the portion after a detector's prefix limit. Unchanged text, UTF-8 BOMs, Unicode,
and CRLF/LF bytes outside selected spans are preserved.

Default planning selects every supported redaction rule. `--rule SL.PII.EMAIL`
selects one; repeat `--rule` for several. **Any remaining known finding blocks
the derivative**, even if it is below the selected scan threshold. Scan
thresholds still determine report counts and policy bindings, but cannot weaken
this zero-known-findings requirement. `--config` and `--profile` must be repeated
at planning and application; an imported plan cannot silently select weaker
settings or increase resource limits.

Private-key blocks are deliberately unsupported. Removing only a detected PEM
header could leave the actual key material, so any recognized private-key
header blocks this operation instead. Handle it manually in a separate copy.

This operates on text bytes, not a format-aware document model. It does not
preserve application semantics, validate JSON/CSV/program syntax, identify all
personal prose, remove every secret format, or make active text such as HTML or
source code harmless. Review the derivative in an appropriate trusted tool.
PDFs, ZIP/Office containers, images, UTF-16, binary/control-byte input, and
incomplete source coverage cannot produce a ready derivative through this command.

## What the plan contains

The separate [plan schema](../schemas/redaction-plan.schema.json) records source
and proposed-output identities, selected rules, merged edit positions, counts,
effective policy, producer version, and snapshot hashes. It contains **no source
text, filenames, matched previews, or evidence fingerprints**. Positions, sizes,
rules, and whole-file hashes are still contextual metadata: keep the plan private.
`redact inspect --format json` shows all edits; console inspection limits its
list to 20 and explicitly announces when additional edits need review.

Checksums are not signatures. Anyone can edit a plan and recompute its checksum;
application therefore regenerates the edits from the current input and compares
the complete plan core. Changing source, source basename, output basename,
producer version, rule selections, positions, expected output, or policy requires
a new plan and review. Historical plans remain inspectable; application requires
the current producer version.

## Publication and limits

The input and prospective output are held in memory, bounded to 4 MiB each and
also to the operator's effective file/total-byte/character limits. Candidate edits
are limited to the smaller of 10,000 and `max_findings`; excess candidates cause
an error, never silent omission. Full source coverage and a finding-free,
complete in-memory output scan are required before candidate bytes reach disk.

The candidate is then written to a private temporary file, closed, reopened and
scanned using its intended filename. The source snapshot is checked again.
Only then are the derivative, native output report, and distinct
[redaction receipt](../schemas/redaction-receipt.schema.json) published through
non-overwriting hard links with byte/identity rechecks. Ordinary failures and
cancellation roll back this operation's publications without deleting an
unrelated replacement. Crashes or hostile output directories can still leave
files; inspect outputs before retrying. Never use privileged execution.

By default the metadata files are `OUTPUT.sharelint-redact.json` and
`OUTPUT.sharelint-redact.report.json`. Override with `--receipt` and `--report`.
All outputs must be distinct new files, never the source or plan. The destination
filesystem must support hard links. No `--force` or in-place option exists.
This receipt is not a ZIP pack receipt and is not accepted by `sharelint verify`;
use `sharelint redact verify`.

## Verification and exits

Redaction verification binds the exact supplied derivative, plan, receipt, and
native report bytes and checks recorded policy, producer, counts, and coverage.
Its resource limits come from the verifier's explicit settings. Optionally pin
an independently obtained digest with `--expected-receipt-sha256`. The verifier
does not receive the original source, rescan current filesystem metadata, rerun
detectors, authenticate the producer, or prove safety. Run a separate `scan` to
assess current content/metadata under today's rules.

- `0`: plan ready, derivative published, or integrity checks completed, depending
  on the subcommand. A ready plan is not an applied transformation.
- `1`: a blocked plan/output or an integrity mismatch; no new derivative is
  published for a blocked application.
- `2`: invalid/unsupported control input, a changed plan/source/policy, unsafe
  output, or an operational error.
- `130`: cancellation. A completed publication may precede an interrupt.

Python callers can use `create_redaction_plan`, `read_redaction_plan`,
`apply_redaction_plan`, and `verify_redaction` with `Path` arguments.
Plan creation returns protected-to-serialize `payload` bytes but does not write
a file itself. Catch `RedactionBlocked` for a policy stop, `VerificationError`
for mismatches, and `DocumentInputError` for invalid control input or safe I/O errors.
