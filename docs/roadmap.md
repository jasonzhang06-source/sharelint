# Roadmap

This roadmap communicates direction, not delivery dates. Priorities may change
with security findings, user evidence, and maintainer capacity.

## Product principles

- Local-only scanning that never transmits scanned content, findings,
  filenames, or telemetry.
- Findings traceable through files, archives, and embedded document parts.
- Sensitive matched values hidden from normal output.
- Explicit coverage and blind spots; unknown content never becomes an implicit
  pass.
- Original files are never modified; a documented transformation creates a new
  output that can be reviewed independently.
- Synthetic, reproducible fixtures for every supported privacy surface.

## Shipped in 0.1 Alpha

- Bounded directory and archive traversal.
- Stable finding identifiers and nested provenance paths.
- Deterministic detectors for paths, text secrets, common PII, and metadata.
- Initial PDF, image, and Office Open XML inspection.
- Console, JSON, SARIF, and static HTML reports with safe defaults.
- Malformed-input, resource-limit, and privacy regression tests.
- Fail-closed deterministic ZIP export followed by reopening and rescanning.
- A minimized receipt that binds the artifact, exact native report, policy,
  ruleset, limits, and measured coverage without making a safety claim.
- A Python 3.11+ package with no third-party runtime package dependencies.

Shipped means implemented and covered by the current repository tests. It does
not mean every format surface is complete; reports continue to expose known
blind spots.

## Shipped in 1.0: native standalone delivery

[Version 1.0.0](https://github.com/jasonzhang06-source/sharelint/releases/tag/v1.0.0)
ships a zero-Python release path for these natively built and verified targets:

- `linux-glibc-x86_64` on `ubuntu-22.04`;
- `windows-x86_64` on `windows-2022`;
- `macos-x86_64` on `macos-15-intel`;
- `macos-arm64` on `macos-15`.

Each job builds and exercises a PyInstaller `onefile` executable. The release
gate uses CPython 3.13.15 and hash-locked build wheels, then checks the exact
archive contents, embedded `BUILD-INFO.json` byte bindings, a same-named
SHA-256 file, and GitHub artifact provenance before attaching assets. The
original 1.0 artifacts were built through that gated pipeline. The publishing
workflow is currently disabled; see the [manual release policy](releasing.md).
Release `v0.1.2` and earlier do not include these archives. All four archives
and their checksums are attached to `v1.0.0`; the
[release workflow](https://github.com/jasonzhang06-source/sharelint/actions/runs/34035839879)
completed successfully. A passing CI artifact by itself is not a public release.

Checksums, build provenance, and platform code signing are different controls.
The initial Windows target is unsigned, and the initial macOS targets are
ad-hoc signed but not Developer ID signed or notarized. Reproducible binaries
and production signing remain evidence-gated work, not current claims.

## Shipped in 2.0: reviewable handoffs

[Version 2.0.0](https://github.com/jasonzhang06-source/sharelint/releases/tag/v2.0.0)
combines the following changes since 1.0:

- Explicit TOML configuration, named policy profiles, and reusable resource limits.
- Offline receipt, report, and ZIP integrity verification, including legacy receipts.
- Aggregate report comparison with conservative coverage and policy-change review.
- Local handoff plans and packing that rejects changed source, policy, or scan snapshots.
- Receipt schema 2.0.0 with ZIP entry indices instead of repeated filenames;
  native scan reports retain schema 1.0.0.
- Predictable cancellation and output-pipe failures, plus file-race hardening.

The 2026-09-14 republication restores the original source tag and native archive
bytes. Intermediate 1.1/1.2/1.2.1/1.3 notes are historical development records;
their tags and releases are not being restored. Install 2.0.0 from GitHub
downloads, its PyPI wheel, or its fixed source tag. The PyPI build `1` preserves
the original runtime code; it is not a new feature release. Previous build
attestations were removed and are not restored by copying the original assets.
See [release details](releases/v2.0.0.md) and [receipt migration](migration-2.md).

## Shipped in 3.0: reviewable text derivatives

[Version 3.0.0](https://github.com/jasonzhang06-source/sharelint/releases/tag/v3.0.0)
adds a bounded, explicit text-redaction workflow on top of the 2.0 contracts:

- `redact plan`, `inspect`, `apply`, and `verify` commands plus typed Python APIs.
- UTF-8 span plans that do not store source text, filenames, previews, or fingerprints.
- Source/policy/producer/output-name bindings and deterministic regenerated edits.
- New-output publication only after source rechecks, output rescanning, complete
  coverage, and zero remaining known findings.
- Separate redaction schemas and receipts; existing scan, batch, handoff, and
  ZIP-receipt contracts remain supported.

The current 3.0.0 public release is a Python wheel. The verified native
standalone archives remain attached to 2.0.0 until a separate native build is
reviewed and published.

## Next P0 workflow gaps

### Auditable policy exceptions

Named profiles, handoff plans, batch preflight, and text-derivative review are
included in the 2.0/3.0 feature line. Narrowly scoped exceptions remain future
work and would need a reason, owner, creation time, and expiry. A report must
show the resolved policy and every exception applied; an expired or malformed
exception must fail closed. This replaces ad-hoc suppression without making a
profile a compliance certificate.

### Scan at the point of handoff

Add bounded local `--staged` and `--stdin` inputs, then maintainable pre-commit
and pre-push hooks. These paths must reuse the same masking, resource budgets,
coverage reporting, and exit-code contract as ordinary scans. `--stdin` needs
an explicit synthetic source identity and format-selection behavior; staged
scanning must inspect the Git index bytes rather than silently substituting the
working tree.

### Reviewable cleaning into a new output

Implemented in 3.0 as `sharelint redact plan`, `inspect`, `apply`, and `verify`.
The initial surface is bounded UTF-8 text, not general document cleanup.
Plans omit source text, application preserves originals and rechecks source,
and new output must be rescanned with complete coverage and no known findings.
A distinct receipt binds plan/output/report/policy. Private-key blocks, document
containers, metadata removal, and format-aware cleaning remain unsupported.

## P1 coverage and review gaps

- Detect bounded, offline Base64, hexadecimal, and percent-encoded candidate
  text without recursively decoding arbitrary data or allowing expansion to
  bypass existing budgets.
- Add versioned regional PII rule packs with synthetic fixtures and explicit
  locale/scope selection. Presence of a pack is not jurisdictional compliance.
- Offer optional, bounded local OCR with clear dependency/model provenance and
  per-page coverage. Pages that were not processed successfully must remain
  explicit gaps; no OCR coverage may be inferred when the capability was not
  run and verified.
- `sharelint verify` is included in 2.0 and validates receipt structures and byte bindings.
  Optional signatures remain future work until a documented key model exists.
  Verification of a receipt is not a rescan or a safety verdict.
- Build desktop drag-and-drop and file-manager integration on the same scanner,
  policy, report, and no-overwrite contracts instead of creating a second
  scanning engine.

## Gap-driven positioning

Adjacent tools solve useful but different parts of the handoff problem. The
roadmap uses those gaps to choose work; it does not claim that ShareLint is
universally better than another category.

| Existing category | Typical strength | ShareLint gap to address |
| --- | --- | --- |
| Repository secret scanners and Git hooks | Fast developer feedback on source history or diffs | Inspect the exact staged/stdin/file/archive handoff locally with document coverage and privacy-safe evidence |
| Metadata cleaners | Focused removal for supported formats | Preview narrowly defined changes, preserve originals, rescan outputs, and record a transformation receipt |
| Hosted enterprise DLP | Central policy, administration, and broad integrations | Provide auditable local profiles and hooks without uploading the selected content |
| Document and OCR tools | Rich rendering, extraction, or visual text recognition | Add optional bounded local OCR and make per-page success or failure visible alongside static coverage |
| Checksums, signing, and provenance tools | Bind bytes to a digest, signer, or build identity | Verify ShareLint receipts and keep artifact integrity, build provenance, signatures, and scan results distinct |

## Later evidence gates

- Public synthetic benchmark corpora with documented precision/recall methods.
- Coverage-guided fuzzing for hostile archives and document structures.
- A stable scanner interface for community-maintained format support.
- Independent security review of hostile document handling.
- Reproducible-build measurement before making reproducibility claims.
- Authenticode, Developer ID/notarization, and sustainable package-manager
  distribution when the signing, account, update, and maintenance processes are
  funded and continuously tested.

## Non-goals

ShareLint will not claim to prove anonymity, certify compliance, remove every
kind of metadata, or call an artifact universally safe merely because no
detector fired. It will not silently modify originals, require uploaded private
files for cloud analysis, validate live credentials over the network, or become
a centralized enterprise DLP control plane. OCR coverage will never be claimed
for a page that was not actually processed by the selected local capability.
