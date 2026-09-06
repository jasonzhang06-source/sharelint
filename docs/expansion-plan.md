# ShareLint expansion checkpoints

Requested work window: 2026-09-06 15:32 UTC through 2026-09-06 23:32 UTC.
This is a work plan, not a claim that the window has elapsed or that all releases
are available. Each version must contain implemented, tested changes before it
is tagged. Published files and tags are immutable. Work stays local-only and
keeps Python 3.11+ and a dependency-free core.

| Version | Intended outcome | State |
| --- | --- | --- |
| 1.1.0 | Explicit TOML configuration, reusable policy profiles, bounded scan limits | Published and installed from public PyPI |
| 1.2.0 | Offline receipt, report, and artifact verification | Native CI passed; publishing |
| 1.2.1 | Cancellation, closed-pipe, and rollback regressions | Local validation |
| 1.3.0 | Validated report comparison and coverage-change review | Planned |
| 2.0.0 | Reviewable handoff plans bound to input and effective policy | Planned |
| 2.1.0 | Bounded batch scanning with per-target results | Planned |
| 3.0.0 | Reviewable text-redaction plans and rescanned new outputs | Planned |
| 3.1.0 | Bounded encoded-content inspection with explicit provenance | Planned |
| 4.0.0 | Private local review workspace and auditable decisions | Planned |
| 4.1.0 | Exact Git staged-content scanning and hook integration | Planned |
| 5.0.0 | Safe local detector packs with deterministic rule identities | Planned |
| 5.1.0 | Integrated first-run workflow, documentation, and hardening | Planned |

The later scope may change in response to evidence. Version numbers alone do
not establish maturity. Major milestones need meaningful capabilities and a
compatibility/migration review; do not create unnecessary breaking changes just
to justify a number. A patch contains actual compatible fixes, not deferred
known defects. Do not skip a failing release gate to meet the requested count.

Every release requires local unit/CLI tests, lint/format/type checks, native CI
on Linux/Windows/macOS, four verified standalone builds, GitHub Release and PyPI
publication, and installation of the publicly served package. Record completed
versions and workflow links below as work proceeds.

## Evidence journal

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
- The existing long-running Goal is paused; no background continuation was
  enabled by this work. Progress in the active conversation is checkpointed here.
