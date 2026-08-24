# Governance

ShareLint is a maintainer-led open source project. This lightweight model keeps
decision-making clear and sustainable for a project currently maintained by one
person.

## Roles

- **Maintainer:** sets scope, merges changes, publishes releases, handles
  security reports, and moderates project spaces.
- **Contributors:** propose changes through issues and pull requests, review
  work, and help improve documentation and tests.

The maintainer has final responsibility for decisions. Significant choices
should be explained in the relevant issue, pull request, or decision record so
the reasoning remains reviewable.

## Decision principles

Changes are prioritized by user impact, privacy and security risk,
reproducibility, compatibility, and ongoing maintenance cost. Rough consensus is
preferred, but lack of consensus does not require the project to accept or
indefinitely delay a change.

Roadmap items are intentions, not commitments or deadlines. Issues and pull
requests may be closed when they are out of scope, inactive, duplicated, or too
costly to maintain.

## Releases

Releases follow semantic versioning where practical. Security fixes may be
released without waiting for unrelated roadmap work. Only the maintainer, or a
delegate explicitly granted release access, may publish official artifacts.
The repeatable release procedure is documented in [docs/releasing.md](docs/releasing.md).

## Adding maintainers

Additional maintainers may be invited after sustained, constructive
contributions and demonstrated care with privacy-sensitive changes. Access is
granted gradually and may be removed when it is no longer needed.

If the project becomes inactive, the MIT License permits the community to fork
and continue the work. Any successor project must not imply that it publishes
official ShareLint releases without authorization.

Community behavior is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), and
vulnerabilities follow [SECURITY.md](SECURITY.md).
