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
- Original files preserved unless the user requests a documented output
  transformation.
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
- A dependency-free default runtime compatible with Python 3.11 and later.

Shipped means implemented and covered by the current repository tests. It does
not mean every format surface is complete; reports continue to expose known
blind spots.

## Next priorities

- Policy profiles and documented suppression workflows.
- Reviewable fixes for metadata and other low-risk transformations.
- Public synthetic benchmark corpora and precision/recall reporting.
- Coverage-guided fuzzing for hostile archives and document structures.
- Turnkey pre-commit and pre-push workflows that run before data leaves the
  machine.

## Later directions

- Reproducible binaries for Linux, macOS, and Windows.
- Package-manager installation where sustainable.
- Optional local OCR with visible availability and coverage status.
- A stable scanner interface for community-maintained format support.
- More Office, archive, media, and regional PII surfaces.
- Independent security review of hostile document handling.
- Desktop drag-and-drop review built on the same core contracts.
- Signed release artifacts and verifiable build provenance.

## Non-goals

ShareLint will not claim to prove anonymity, certify compliance, upload private
files for mandatory cloud analysis, silently modify originals, or call an
artifact universally safe merely because no detector fired.
