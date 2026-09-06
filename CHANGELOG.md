# Changelog

All notable changes to ShareLint will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-09-06

The first stable release maintains the existing scanner and machine-readable
contracts. It consolidates the previously unpublished cross-platform delivery
work with focused usability fixes; no new scanning features are introduced.

### Added

- Configured native PyInstaller `onefile` build and smoke-test jobs for glibc
  Linux x86-64, Windows x86-64, Intel macOS, and Apple silicon macOS.
- Configured the next release pipeline to validate exact standalone archive
  contents, publish same-named SHA-256 files, and request GitHub artifact
  attestations before attaching assets or publishing to PyPI.
- Added format-version 2 `BUILD-INFO.json` records with the native target,
  selected build-component versions, build-lock and executable digests,
  name/size/SHA-256/typecode native-file identities, reviewed static-component
  evidence, and equal PyInstaller Analysis/PKG name/type inventory summaries.
- Added `THIRD-PARTY-NOTICES.txt`, a format-version 2 native-license catalog,
  and a fail-closed per-target gate covering Linux/Windows mimalloc, both
  Windows zlib copies, macOS SQLite, and the other matched frozen components
  before the four-target release set can proceed.
- Added canonical, bounded sdist normalization and an independent byte check for
  stable USTAR/gzip metadata without claiming reproducible wheels or binaries.
- Added a shared release-asset verifier that rejects extra members, unsafe
  types, non-canonical metadata, hidden/trailing archive bytes, incorrect
  licenses, mismatched executable bytes, and incomplete four-target sets.

### Changed

- Console and HTML reports now label non-blocking findings as `REVIEW` while
  preserving exit code `0` and the existing JSON/SARIF `pass` machine verdict.
- The demo now begins with an explicit synthetic-data banner stating that no
  personal files were read.
- Locked standalone builds to CPython 3.13.15 and hash-verified binary wheels;
  pinned every GitHub Action to an immutable commit SHA.
- Changed tagged publication to stage a private draft, attach and re-download
  byte-identical assets idempotently, publish PyPI through OIDC, and expose the
  GitHub Release only after every prior gate succeeds.
- Established the 1.x compatibility policy for existing commands, exit codes,
  public Python exports, and versioned report/receipt formats.
- Corrected the pack help example to use fully inspectable input and made its
  coverage requirement explicit. Unknown rule errors no longer echo input.

### Documentation

- Documented that standalone archives are still forthcoming, including the
  exact target matrix, zero-Python and uv-first installation paths, onefile
  temporary-directory requirements, and initial Windows/macOS signing limits.
- Distinguished checksum integrity, GitHub build provenance, platform code
  signing, notarization, and ShareLint pack receipts.
- Reframed the roadmap around auditable policy exceptions, handoff hooks,
  non-destructive cleaning, bounded decoding/OCR, receipt verification, and
  explicit non-goals.
- Updated package status and user-facing version information to 1.0.0; PDF/image
  OCR and other future capabilities remain explicitly outside this release.

## [0.1.2] - 2026-08-24

### Added

- Added native Ubuntu, Windows, and macOS CI coverage at the minimum and latest
  supported Python versions, plus wheel installation smoke tests on all three.
- Added fail-closed presence checks for Windows alternate data streams,
  Linux/macOS extended attributes, and macOS resource forks without disclosing
  hidden names or values.
- Added native regression contracts for Windows junctions, Windows data streams,
  and Linux/macOS extended attributes.

### Changed

- Made redirected CLI output consistently UTF-8 across legacy Windows code pages.
- Treat Windows reparse points as filesystem links and never traverse them.
- Re-evaluate policy and coverage on the final source scan before publishing a
  packed artifact, so newly added hidden metadata blocks publication.
- Bind packed-file receipts to the bytes actually read during publication, and
  reject filesystem identity or metadata changes detected during that read.

## [0.1.1] - 2026-08-24

### Added

- Added `demo --report` for atomically writing a rendered synthetic-demo report.
- Added an architecture guide, documentation index, and installation troubleshooting guide.

### Changed

- Made isolated PyPI installation the primary path in both READMEs.
- Clarified the first-run experience, feedback paths, contribution options, and issue triage.

## [0.1.0] - 2026-08-24

### Added

- Local-only scanning for directories, archives, Office documents, PDFs, images, and text.
- Recursive provenance for findings in nested share bundles.
- Privacy-preserving console, JSON, SARIF, and HTML reports.
- Deterministic fail-closed packaging with hash-bound receipts.
- Explicit coverage gaps and bounded handling of untrusted archives.
- Synthetic demonstration bundle, contributor governance, and security documentation.
- Continuous integration across Python 3.11, 3.12, 3.13, and 3.14.
- A branch-aware 75% coverage floor enforced in CI and release verification.
- CodeQL analysis, dependency update automation, and a Trusted Publishing release workflow.

[Unreleased]: https://github.com/jasonzhang06-source/sharelint/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/jasonzhang06-source/sharelint/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/jasonzhang06-source/sharelint/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/jasonzhang06-source/sharelint/releases/tag/v0.1.0
