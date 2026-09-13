# Installation and troubleshooting

This guide targets ShareLint 2.0.0. Download a standalone archive from
[GitHub v2.0.0](https://github.com/jasonzhang06-source/sharelint/releases/tag/v2.0.0),
or install the original fixed-tag source with Python 3.11+ and Git.
[PyPI currently provides 1.0.0](https://pypi.org/project/sharelint/1.0.0/);
the original PyPI 2.0.0 files were deleted and their filenames cannot be reused.
Ordinary package-index installation or upgrade commands do not obtain 2.0.0.
Downloads and installation use the network; scanning itself has no upload,
telemetry, account, or network feature.

## No Python installed

### First choice: standalone archive

The standalone archive includes the interpreter and launcher. Select your
platform from the [2.0.0 downloads](../README.md#no-python-standalone-archive).
Use only the archive and matching checksum visibly attached to that completed
GitHub Release. An ordinary CI artifact is not a release download.

The archive names and measured build runners are listed in the
[standalone target matrix](platform-support.md#standalone-release-target-matrix).
For an archive attached to a completed release, complete
[standalone archive verification](#standalone-archive-verification) before
running the executable.

## pipx source installation

With Python 3.11+, Git, and [pipx](https://pipx.pypa.io/stable/) installed,
install the fixed 2.0.0 source tag:

```bash
pipx install 'git+https://github.com/jasonzhang06-source/sharelint.git@v2.0.0'
sharelint --version
sharelint demo
```

The version command must print `ShareLint 2.0.0`. To replace an existing pipx
installation with that same source version, use the explicit source again:

```bash
pipx install --force 'git+https://github.com/jasonzhang06-source/sharelint.git@v2.0.0'
```

To remove a pipx installation:

```bash
pipx uninstall sharelint
```

## Standard virtual environment

On Linux or macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install 'git+https://github.com/jasonzhang06-source/sharelint.git@v2.0.0'
sharelint --version
sharelint demo
```

On Windows PowerShell:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install 'git+https://github.com/jasonzhang06-source/sharelint.git@v2.0.0'
sharelint --version
sharelint demo
```

If PowerShell policy prevents activation, do not weaken the machine-wide policy.
Call the environment's executables directly:

```powershell
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install 'git+https://github.com/jasonzhang06-source/sharelint.git@v2.0.0'
.\.venv\Scripts\sharelint.exe demo
```

These source installation commands require Git as well as Python 3.11+.
The same package targets Linux, Windows, and macOS, but validation is tied to a
specific CI commit and writable outputs require filesystem hard-link support.
Read [Platform support](platform-support.md) before using FAT/exFAT, network,
synchronized, or virtual filesystems.

Do not use `sudo pip install` and do not bypass an
`externally-managed-environment` error with `--break-system-packages`. That
message means the operating system protects its Python installation. Use the
fixed-tag pipx installation or a virtual environment instead.

## Standalone archive verification

This section applies only after a tagged GitHub Release actually lists the
standalone archive and its same-named `.sha256` file. The examples select
2.0.0; use the target matching your computer.

On Linux, verify the archive checksum before extraction:

```bash
sha256sum --check sharelint-v2.0.0-linux-glibc-x86_64.tar.gz.sha256
```

On macOS, use the matching Intel or Apple silicon filename:

```bash
shasum -a 256 -c sharelint-v2.0.0-macos-arm64.tar.gz.sha256
```

On Windows PowerShell:

```powershell
$Archive = ".\sharelint-v2.0.0-windows-x86_64.zip"
$Expected = ((Get-Content "$Archive.sha256") -split '\s+')[0]
$Actual = (Get-FileHash -Algorithm SHA256 $Archive).Hash
if ($Actual.ToLowerInvariant() -ne $Expected.ToLowerInvariant()) {
    throw "ShareLint archive checksum mismatch"
}
```

A matching checksum detects corruption or a mismatch with that checksum file;
it does not prove who published either file. The 2026-09-14 republication
restores the original archive bytes and checksum files. Previous GitHub
attestations were removed; a working `gh attestation verify` result is not
claimed for these restored downloads. The included `BUILD-INFO.json` preserves
the original build record, but does not independently authenticate the publisher.

After verification, extract and run on Linux:

```bash
tar -xzf sharelint-v2.0.0-linux-glibc-x86_64.tar.gz
cd sharelint-v2.0.0-linux-glibc-x86_64
./sharelint --version
./sharelint demo
```

On Apple silicon macOS (use `macos-x86_64` instead on an Intel Mac):

```bash
tar -xzf sharelint-v2.0.0-macos-arm64.tar.gz
cd sharelint-v2.0.0-macos-arm64
./sharelint --version
./sharelint demo
```

On Windows PowerShell:

```powershell
Expand-Archive .\sharelint-v2.0.0-windows-x86_64.zip -DestinationPath .
Set-Location .\sharelint-v2.0.0-windows-x86_64
.\sharelint.exe --version
.\sharelint.exe demo
```

The extracted directory also contains the ShareLint, Python, PyInstaller, and
native-runtime notices, including `THIRD-PARTY-NOTICES.txt`. Keep every license
and notice file with redistributed copies of the executable.

Format-version 2 of `BUILD-INFO.json` binds the target, selected build-component
versions, aggregate build-lock digest, executable, and the exact notices. Each
frozen native file identity contains its name, size, SHA-256, and CArchive
typecode (`b`). The record also binds the format-version 2 native-license
catalog, target-specific static-component evidence, and equal summaries of
PyInstaller's canonical Analysis and PKG name/type inventories. The native
release gate rejects an unknown or malformed native entry, unequal summaries, a
name mismatch with the executable's CArchive, a recorded identity that does not
match the executable, or a required component without reviewed notice coverage.
Because the record and notices are inside the archive, its checksum covers
their exact bytes. They remain transparency evidence, not an
independent trust root, complete SBOM, legal certification, or
reproducible-build proof.

If any expected notice file is absent, `BUILD-INFO.json` is not format version 2,
or an archive/checksum pair fails verification, do not run or redistribute that
copy. Delete the extracted directory and obtain the matching archive and
checksum again from the completed GitHub Release. Use only assets visibly
listed on that release page; a normal CI artifact is not a substitute.

## Standalone executable does not start

First confirm that the target matches the host. `macos-arm64` is for Apple
silicon, `macos-x86_64` is for Intel Macs, and the Linux archive requires an
x86-64 glibc system. There is no standalone Linux ARM64, musl/Alpine, Windows
ARM64, or 32-bit target in the matrix. The fixed-tag source installation is an
alternative where Python 3.11+ and Git are available; unlisted hosts have not
been validated by the native release matrix.

On Linux or macOS, extraction should retain the executable bit. If a trusted,
verified copy lost it, restore only the user execute bit:

```bash
chmod u+x ./sharelint
```

The PyInstaller `onefile` launcher expands its own bundled runtime into a unique
temporary directory before ShareLint starts. It does not extract the documents
being scanned. On POSIX, that temporary filesystem must allow execution and
symbolic links. If the default temporary directory is mounted `noexec` or lacks
symbolic-link support, choose a user-owned directory on a local filesystem that
supports both:

```bash
mkdir -p "$HOME/.cache/sharelint-tmp"
chmod 700 "$HOME/.cache/sharelint-tmp"
TMPDIR="$HOME/.cache/sharelint-tmp" ./sharelint --version
```

The directory must already exist. If the replacement filesystem is also
`noexec` or lacks symbolic links, this will still fail. A crash or forced stop
can leave an `_MEI...` runtime directory behind; remove a leftover only after
confirming that no ShareLint process is using it.

Do **not** work around a failure with `sudo`, a root shell, or Windows **Run as
administrator**. ShareLint does not require elevation, and a privileged
`onefile` launch increases the impact of a compromised launcher, temporary
directory, or hostile input.

The first Windows standalone executable is not Authenticode-signed. SmartScreen
can report an unrecognized app, and managed policy may block it completely. The
first macOS executables are ad-hoc signed but do not have Developer ID
distribution signing or Apple notarization, so Gatekeeper can warn or block.
After verifying the checksum, and only when the device owner's
policy permits unsigned software:

- For one Windows file, open **More info → Run anyway** in the SmartScreen
  dialog if that option is offered.
- For one macOS file, Control-click the executable in Finder and choose
  **Open**, or use **System Settings → Privacy & Security → Open Anyway** for
  that blocked file.

If the per-file option is absent or managed policy blocks it, stop and use the
fixed-tag source installation if permitted. Do not disable SmartScreen or Gatekeeper globally, remove macOS
quarantine attributes, use `sudo`, or choose **Run as administrator**.

## `sharelint: command not found`

The standalone archive is not an installer and does not change `PATH`. Run
`./sharelint` from its extracted directory on Linux/macOS or
`.\sharelint.exe` from that directory in PowerShell.

First confirm that the selected installer can see the application:

```bash
pipx list
```

For pipx, run `pipx ensurepath`, then open a new terminal. For an ordinary
virtual environment, activate it before running
`sharelint`. You can also verify the package through the active interpreter:

```bash
python -m pip show sharelint
python -m sharelint --version
```

## Python version errors

Check the interpreter selected by your shell:

```bash
python --version
python3 --version
```

On Windows, also check the Python launcher:

```powershell
py --version
```

ShareLint does not support Python 3.10 or older. Installing a newer Python does
not always change the existing `python` command; explicitly select the newer
interpreter when creating the virtual environment.

## Exit status and incomplete coverage

The CLI uses these stable exit codes:

| Code | Meaning |
| ---: | --- |
| `0` | The command completed and the selected gate did not block. |
| `1` | A finding met the threshold, strict coverage failed, or `pack` was blocked. |
| `2` | Usage was invalid, the target was unreadable, or another operational error occurred. |
| `130` | The user interrupted the command. Review completed outputs before retrying. |

`sharelint demo` intentionally returns `0` after showing a synthetic blocked
example; its console banner says that it generated synthetic data and read no
personal files. A normal `scan` can also return `0` while reporting `INCOMPLETE`
unless `--strict` was selected. Use this in automation when every required
surface must be inspected:

```bash
sharelint scan ./handoff --strict --fail-on high
```

Console and HTML output say `REVIEW` when a complete scan retained findings but
none reached the selected `--fail-on` threshold. This is deliberately
non-blocking: the exit status is `0`, while JSON and SARIF retain
`summary.verdict: "pass"` for compatibility with the machine contract. `PASS`
means no findings were retained. Neither status is a safety guarantee.

PDF rendered pages and image pixels are not OCR-scanned in the dependency-free
baseline. Their coverage gap is expected and visible. `pack` is stricter and
will not publish an archive while any required surface is partial, skipped, or
errored.

## Report output errors

ShareLint refuses to overwrite existing reports, demo bundles, archives, and
receipts. Choose a new output path or deliberately move the old file first.
Reports for a directory scan must also be written outside that directory.

Writable outputs use a hard link in the destination directory to preserve the
no-overwrite guarantee. FAT/exFAT, some network shares, and some synchronized or
virtual filesystems can reject that operation. If an atomic-write error occurs,
choose a new path on a local NTFS, APFS, ext4, or other hard-link-capable
filesystem. Changing the standalone launcher's temporary directory does not fix
an output destination that lacks hard-link support.

To create a local HTML report from synthetic data without printing HTML into
the terminal:

```bash
sharelint demo --format html --report sharelint-demo.html
```

The report is self-contained. It can contain sensitive context such as masked
finding types and filenames, so protect it even though complete matched values
are not included.

## Ask for help safely

Collect only the following before opening a
[setup question](https://github.com/jasonzhang06-source/sharelint/issues/new?template=question.yml):

```bash
sharelint --version
python --version
```

Describe the operating system, installation method, sanitized command, and
exact generic error class. Never attach a real input document, raw finding,
secret, personal identifier, private local path, or confidential report. Report
possible vulnerabilities privately according to the
[security policy](../SECURITY.md).
