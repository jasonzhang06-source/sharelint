# Platform support

ShareLint is designed as a Python 3.11+ command-line tool for Linux, Windows,
and macOS. All three platforms install the same pure-Python package from PyPI,
and the default runtime has no third-party dependencies.

Platform support and scan coverage are separate claims. Running on an operating
system does not mean every document surface is fully inspected. Every report
continues to expose unsupported, partial, skipped, malformed, encrypted, and
budget-limited surfaces as coverage gaps.

## Validation matrix

The current repository configures these CI jobs:

| Platform | Python versions in CI | Validation |
| --- | --- | --- |
| Ubuntu | 3.11, 3.12, 3.13, 3.14 | Complete unit and CLI contract suites |
| Windows | 3.11, 3.14 | Portable unit/CLI contracts and Windows-specific checks |
| macOS | 3.11, 3.14 | Portable unit/CLI contracts and macOS-specific checks |

Check the [CI result](https://github.com/jasonzhang06-source/sharelint/actions/workflows/ci.yml)
for the exact commit or tag you intend to use. A configured job is not evidence
that a particular run passed, and a job added after a release does not
retroactively validate that release. The PyPI `OS Independent` classifier
describes package portability; it is not a guarantee for every filesystem,
shell, locale, or security configuration.

The symbolic-link contract test may be skipped on Windows when the runner lacks
permission to create a link. That is an environment limitation, not a weaker
product rule: ShareLint still refuses to follow an existing symbolic link at
the selected boundary and refuses to publish output through an existing link.
The native Windows junction contract is mandatory on GitHub-hosted Windows
runners. Built wheels are installed and smoke-tested on Ubuntu, Windows, and
macOS after the source suites pass.

## Installation

`pipx` and `uv` provide the same commands on all three platforms:

```text
pipx install sharelint
```

```text
uv tool install sharelint
```

The shell-specific virtual-environment commands are documented in
[Installation and troubleshooting](troubleshooting.md#standard-virtual-environment).
Python 3.10 and older are not supported.

## Filesystem requirements

ShareLint checks for hidden platform filesystem surfaces before classifying the
ordinary file bytes:

- On Windows, it enumerates NTFS data-stream records. A named alternate data
  stream is a high-severity finding and an explicit skipped surface.
- On Linux and macOS, it probes whether extended attributes are present. This
  includes macOS resource forks exposed through extended attributes.

The first implementation is presence-only: stream and attribute names, sizes,
and values are neither copied into reports nor content-scanned. Presence or an
enumeration failure therefore makes coverage incomplete and blocks `pack`.
This avoids silently reporting hidden bytes as clean while keeping unbounded
attribute values out of memory. Ordinary files such as macOS AppleDouble
`._name` sidecars are still scanned as files; ShareLint does not currently claim
specialized interpretation of the AppleDouble format.

### Writable outputs

Commands that write reports, demo bundles, archives, or receipts publish from a
temporary file in the destination directory using a hard link. This preserves
the no-overwrite contract without replacing an existing destination. The
destination filesystem must therefore support hard links. FAT/exFAT volumes
and some network, synchronized, or virtual filesystems may not provide the
required operation even when the operating system itself is supported.

If publication cannot be completed with that primitive, ShareLint reports an
operational error instead of falling back to an overwrite-prone write. Choose a
new path on a local filesystem that supports hard links; do not weaken the
no-overwrite check. On POSIX platforms, tests also verify owner-only output
permission bits. On Windows, access is governed by Windows and inherited
directory ACLs, so keep report and receipt destinations access-controlled.

## Reporting a platform problem

Open a [setup question](https://github.com/jasonzhang06-source/sharelint/issues/new?template=question.yml)
with the operating system, filesystem type, Python version, installation
method, sanitized command, and generic error class. Never attach a real input
document, raw finding, secret, personal identifier, private local path, or
confidential report.
