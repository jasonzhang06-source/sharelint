# Platform support

ShareLint is a command-line tool for Linux, Windows, and macOS. The Python
package requires Python 3.11+ and has no third-party runtime package
dependencies. A separate PyInstaller `onefile` executable can bundle the
interpreter and launcher for people who do not have Python installed; that
executable has a larger trusted computing base even though it needs no external
Python installation.

Platform support and scan coverage are separate claims. Running on an operating
system does not mean every document surface is fully inspected. Every report
continues to expose unsupported, partial, skipped, malformed, encrypted, and
budget-limited surfaces as coverage gaps.

## Python package validation matrix

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

## Standalone release target matrix

The repository now configures a native standalone build and smoke test for four
OS/architecture targets. The archives are **in CI validation for the next tagged
release**. Release `v0.1.2` and earlier do not contain them; an asset is available
only after it is visibly attached to a completed
[GitHub Release](https://github.com/jasonzhang06-source/sharelint/releases).

| Native build runner | Target identifier | Planned release archive | Validation boundary |
| --- | --- | --- | --- |
| `ubuntu-22.04` | `linux-glibc-x86_64` | `sharelint-v{version}-linux-glibc-x86_64.tar.gz` | x86-64 glibc build; not a musl/Alpine or Linux ARM64 claim |
| `windows-2022` | `windows-x86_64` | `sharelint-v{version}-windows-x86_64.zip` | 64-bit Windows build; not Windows ARM64 or 32-bit |
| `macos-15-intel` | `macos-x86_64` | `sharelint-v{version}-macos-x86_64.tar.gz` | Native Intel macOS runner |
| `macos-15` | `macos-arm64` | `sharelint-v{version}-macos-arm64.tar.gz` | Native Apple silicon runner |

`{version}` is the package version without the leading `v`. Each archive has a
same-named `.sha256` file. Inside it is one top-level directory named after the
archive without `.tar.gz` or `.zip`, containing:

- `sharelint` (`sharelint.exe` on Windows);
- `BUILD-INFO.json` (target, toolchain versions, lock digest, and executable digest);
- `README.txt`;
- `LICENSE.txt`;
- `PYTHON-LICENSE.txt`;
- `PYINSTALLER-LICENSE.txt`;
- `THIRD-PARTY-NOTICES.txt`.

These are native builds, not cross-platform executables. A Windows `.exe`
cannot run on Linux, and an Intel Mac binary is not the Apple silicon target.
That does not mean a contributor must switch operating systems for routine
work: use the package or target for the current host and let the four native CI
jobs test the others. Reproducing an OS-specific host feature manually still
requires that OS.

Format-version 2 of `BUILD-INFO.json` binds the executable and build locks. Each
frozen native file is recorded as a `name`, `size`, `sha256`, and CArchive
`typecode` (`b`) object. The record also contains target-specific
static-component evidence and equal SHA-256 summaries of PyInstaller's
canonical Analysis and PKG name/type inventories. The record and
`THIRD-PARTY-NOTICES.txt` are carried inside the checksummed and attested
archive. They are not an independent trust root, a complete SBOM, legal
certification, or proof that the binary is reproducible.

### Native inventory and license gate

Each native job inspects the executable produced on that target instead of
assuming that all four operating systems freeze the same libraries. The gate
reconciles the native entries embedded in the PyInstaller CArchive with the
build's Analysis and PKG inventories, records their identities, maps dynamic
files and reviewed target-specific static components to the pinned
format-version 2 native-license catalog, and requires the matching notice text.
An unknown or malformed entry, unequal Analysis/PKG summaries, a name mismatch
with the CArchive, or a notice-free component stops that target before an
archive can be attached.
The combined release gate succeeds only after the Linux, Windows, Intel macOS,
and Apple silicon macOS jobs all pass.

Notable static rules include mimalloc 2.1.2 for the Linux and Windows CPython
cores, two separate Windows zlib records (PyInstaller bootloader 1.3.2 and
CPython core 1.3.1), and SQLite 3.50.4 when `_sqlite3*.so` is present in either
macOS target. The catalog also covers the other matched native components.

This mechanism is deliberately fail closed, but its catalog remains a reviewed
project artifact rather than an automated legal opinion. A new CPython,
PyInstaller, runner image, or native dependency can change the inventory and
must be reviewed instead of being silently accepted. The four target outputs
are still awaiting their first complete native CI validation for the next
tagged release; this repository does not claim that standalone files have
already been published.

The runner is the measured baseline, not a promise about every OS release. In
particular, the Linux archive is built against glibc on Ubuntu 22.04; use the
Python package on an unlisted architecture, musl-based distribution, or host
where the standalone executable does not run.

## Installation order

Once a tagged release visibly contains the standalone archives, that is the
first-choice path for a user without Python. Until then, use `uvx`, which can
obtain a compatible Python automatically:

```text
uvx sharelint demo
```

For a persistent uv installation:

```text
uv tool install sharelint
uv tool update-shell
```

`pipx` remains appropriate when Python 3.11+ and pipx are already installed:

```text
pipx install sharelint
```

The shell-specific virtual-environment commands are documented in
[Installation and troubleshooting](troubleshooting.md#standard-virtual-environment).
Python 3.10 and older are not supported by the Python package.

## Standalone runtime and platform security

The standalone executable uses PyInstaller `onefile` mode. At startup, its
launcher expands the bundled interpreter and support libraries into a unique
temporary directory, starts ShareLint, and normally removes that directory on
exit. This is **program-runtime extraction**; ShareLint still does not extract
the files, archives, or documents selected for scanning.

On POSIX systems, the runtime temporary filesystem must permit execution and
symbolic links. A `noexec` mount or filesystem without symbolic-link support can
prevent the executable from starting. A crash or forced termination can leave
an `_MEI...` runtime directory behind. See PyInstaller's documentation for
[onefile operation](https://pyinstaller.org/en/stable/operating-mode.html#how-the-one-file-program-works)
and [POSIX symbolic-link requirements](https://pyinstaller.org/en/stable/common-issues-and-pitfalls.html#requirements-imposed-by-symbolic-links-in-frozen-application).

Run ShareLint as the ordinary signed-in user. Do not use `sudo`, a root shell,
or Windows **Run as administrator** to work around a startup, permission, or
filesystem error. Elevation is unnecessary for scanning user-selected content
and increases the impact of a compromised input, launcher, or temporary
directory.

The first standalone release line has these signing limitations:

- **Windows:** the executable has no Authenticode publisher signature.
  Microsoft Defender SmartScreen can show an unrecognized-app warning, and
  organizational policy may prevent an override. A checksum or GitHub
  attestation does not make SmartScreen display a verified publisher.
- **macOS:** PyInstaller performs ad-hoc signing, not Developer ID distribution
  signing, and the archive is not Apple-notarized. Gatekeeper can warn or block
  it. A checksum or GitHub attestation is not Apple notarization.
- **Linux:** the archive is not a distribution package and makes no package
  manager or desktop trust-store integration claim.

Do not disable SmartScreen or Gatekeeper globally. Verify the download first,
follow the local or organizational security policy, and use the PyPI/uv path if
unsigned standalone software is not permitted. Microsoft documents how
[SmartScreen reputation](https://learn.microsoft.com/windows/apps/package-and-deploy/smartscreen-reputation)
works; Apple documents
[Gatekeeper](https://support.apple.com/guide/security/gatekeeper-and-runtime-protection-sec5599b66df/web)
and [notarization](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution).

## Checksums, provenance, and code signing

The release-side `.sha256` file lets a user detect a corrupted archive or a
mismatch with the checksum they obtained. It does not identify the publisher:
an attacker who can replace the archive may also be able to replace its checksum.

The standalone release workflow also requests GitHub artifact attestations.
After a release containing the assets exists, the archive's provenance can be
checked with GitHub CLI:

```text
gh attestation verify sharelint-vX.Y.Z-linux-glibc-x86_64.tar.gz --repo jasonzhang06-source/sharelint
```

That verifies that GitHub has an attestation for those exact bytes associated
with this repository's workflow identity. It does not certify that the code is
safe, reproduce the build independently, create an Authenticode/Developer ID
signature, or notarize a macOS binary. Conversely, an OS code signature would
identify a platform publisher but would not replace a build-provenance check.

These release checks are also separate from a `sharelint pack` receipt. A pack
receipt binds a user's output archive to a scan report and policy; it says
nothing about where the ShareLint executable itself was built.

### Source distribution normalization

The tagged workflow also normalizes the Python source distribution after
building it. Given the same member names, contents, and executable-bit choices,
the normalizer sorts members, emits USTAR with fixed ownership and timestamps,
uses fixed directory/file modes and a fixed gzip header, and then independently
checks the resulting bytes. It rejects links, special files, traversal,
duplicates, excess sizes or member counts, multiple roots, and hidden trailing
data instead of attempting to repair an ambiguous archive.

This is a reproducible **sdist normalization contract**, not a claim that the
wheel, standalone executables, or mutable native runner toolchains are
reproducible. Content changes still produce different source distributions.

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
