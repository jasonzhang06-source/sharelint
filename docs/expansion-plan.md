# Historical development checkpoints through 2.0

This record preserves the development checkpoints originally recorded in
September 2026. It is not a current installation guide or a promise that the
intermediate releases remain downloadable. As of the 2026-09-14 republication,
the public upgrade path is 1.0 to 2.0: the original 2.0 source and native assets
are restored, while intermediate GitHub tags/releases remain removed. PyPI
currently provides 1.0.0; the original 2.0.0 files were deleted and their filenames
cannot be reused.

| Historical checkpoint | Included work | Current disposition |
| --- | --- | --- |
| 1.1.0 | Explicit TOML configuration, reusable policy profiles, bounded scan limits | Included in 2.0; historical record only |
| 1.2.0 | Offline receipt, report, and artifact verification | Included in 2.0; historical record only |
| 1.2.1 | Cancellation, closed-pipe, and rollback regressions | Included in 2.0; historical record only |
| 1.3.0 | Validated report comparison and coverage-change review | Included in 2.0; historical record only |
| 2.0.0 | Reviewable handoff plans and privacy-minimized receipt migration | Original tag and native assets restored |

Current behavior and compatibility are described in the
[2.0 release notes](releases/v2.0.0.md) and [migration guide](migration-2.md).
Publication now follows the [manual release policy](releasing.md); the
automated publishing workflow remains disabled. Historical workflow links and
test counts below are evidence recorded during development, not a claim that
the workflows were rerun or their old release pages are available today.

## Historical evidence journal

- Start: clean `main` at `da2e3b6`; public baseline is `v1.0.0`.
- 1.1.0: source `24ff09a`; 121 local tests passed, two platform skips,
  77.83% coverage. [Native CI](https://github.com/jasonzhang06-source/sharelint/actions/runs/34043185279)
  and [release pipeline](https://github.com/jasonzhang06-source/sharelint/actions/runs/34043497065)
  passed. GitHub published at 15:53 UTC with eight standalone/checksum assets;
  fresh public-PyPI installation and isolated wheel smoke verification passed.
- 1.2.0 local gate: 138 tests passed, two platform skips, 80.50% coverage;
  lint/format/type checks, build/sdist normalization, package metadata checks,
  and isolated installed-wheel receipt verification passed. Native CI and
  public publication are not yet claimed.
- The first 1.2.0 CI caught Python 3.11 Enum membership incompatibility before
  tagging. Fixed at `36a8008`; all 17 checks passed in
  [CI](https://github.com/jasonzhang06-source/sharelint/actions/runs/34044550732).
  An exact-commit wheel also passed isolated Python 3.11 installation tests;
  real public-1.1 receipts passed verification. The release tag points to the
  corrected commit, never the failed candidate.
- 1.2.0: [publication](https://github.com/jasonzhang06-source/sharelint/actions/runs/34044812594)
  passed; the publicly served PyPI wheel was reinstalled without cache and
  passed the isolated Python 3.11 smoke test, including receipt verification.
- 1.2.1: exact source `74d84a5`, 143 tests passed and two skipped, 80.66%
  coverage, lint/format/types, build metadata, and isolated Python 3.11 wheel
  smoke passed. [Native CI](https://github.com/jasonzhang06-source/sharelint/actions/runs/34045217834)
  passed all operating-system and standalone targets.
- 1.3.0 local gate: 155 tests passed and two skipped, 81.50% coverage; comparison
  schema, privacy, CLI, and Python 3.11 tests passed. No public release claimed yet.
- 1.2.1 [publication](https://github.com/jasonzhang06-source/sharelint/actions/runs/34045514747)
  succeeded and its public PyPI wheel passed isolated Python 3.11 verification.
- 1.3.0 source `e3edf75`: [native CI](https://github.com/jasonzhang06-source/sharelint/actions/runs/34045515846)
  and [publication](https://github.com/jasonzhang06-source/sharelint/actions/runs/34046052030)
  passed. The publicly served wheel was installed without cache and passed its
  exact-version isolated smoke test, including offline verification and comparison.
- 2.0.0 local gates: 172 tests passed, two platform skips, 82.52% branch coverage;
  lint/format/types, legacy public-1.1 receipt verification, and Python 3.11
  source/installed-wheel planning, packing, and verification checks passed.
  New v2 receipts remove filename repetition demonstrated by a synthetic
  non-blocking filename regression. No native/public release is claimed yet.
