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
Original 1.0 artifacts were built through that gated pipeline. The publishing
workflow is currently disabled; see the [manual release policy](releasing.md).
Release `v0.1.2` and earlier do not include these archives. All four archives
and their checksums are attached to `v1.0.0`; the
[release workflow](https://github.com/jasonzhang06-source/sharelint/actions/runs/34035839879)
completed successfully. A passing CI artifact by itself is not a public release.

Checksums, build provenance, and platform code signing are different controls.
The initial Windows target is unsigned, and the initial macOS targets are
ad-hoc signed but not Developer ID signed or notarized. Reproducible binaries
and production signing remain evidence-gated work, not current claims.

## Next P0 workflow gaps

### Policy profiles and auditable exceptions

Add named profiles for recurring sharing contexts and narrowly scoped
exceptions that have a reason, owner, creation time, and expiry. A report must
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

Design `sharelint clean --plan` before enabling transformations. The plan must
list proposed operations without changing source bytes. An apply mode must
write a distinct output, never modify the original, rescan the completed
output, and issue a transformation receipt binding input, plan, output, policy,
and measured coverage. Early transforms should be narrow and format-specific;
ShareLint must not claim to remove all metadata.

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
- Add `sharelint verify` to validate receipt schemas and byte bindings, with
  optional receipt signatures when a documented key model exists. Verification
  of a receipt is not a rescan or a safety verdict.
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
