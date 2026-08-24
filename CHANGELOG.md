# Changelog

All notable changes to ShareLint will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/jasonzhang06-source/sharelint/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/jasonzhang06-source/sharelint/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/jasonzhang06-source/sharelint/releases/tag/v0.1.0
