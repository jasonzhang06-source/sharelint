ShareLint @VERSION@ — portable @TARGET@
========================================

This folder contains a self-contained ShareLint command-line program. It does
not need a system Python installation and it does not upload scanned content.

Start here
----------

@RUN_PREFIX@ demo
@RUN_PREFIX@ scan "PATH-TO-A-FILE-OR-FOLDER"
@RUN_PREFIX@ pack "PATH-TO-A-FOLDER" -o "safe-to-share.zip"

`demo` reads only a temporary synthetic sample. `scan` never changes the input.
`pack` creates a new ZIP only after its policy and coverage checks pass.

What the result means
---------------------

A passing result means that no configured blocker was found on the surfaces
listed in the report. It is not a guarantee that a file is safe, anonymous, or
compliant. Coverage gaps remain visible and block `pack`.

Privacy and runtime notes
-------------------------

* Scanning and reporting are local. There is no account, upload, or telemetry.
* Matched values are masked. Reports and receipts can still reveal filenames and
  structural metadata, so keep them private unless you have reviewed them.
* The one-file program unpacks its own embedded Python runtime to a temporary
  directory while it runs. It never extracts scanned archives or Office files to
  disk. On Linux and macOS, the temporary filesystem must allow both execution
  and symbolic links; a `noexec` mount can prevent startup.
* Do not run the program as root, Administrator, setuid, or from a directory that
  another user can modify.
* This build targets @TARGET@ only. Download the matching asset for another OS or
  CPU architecture.
* The first Windows build is not Authenticode-signed. After verifying the archive,
  use SmartScreen's per-file "More info" then "Run anyway" only when device policy
  permits it; otherwise use the PyPI/uv installation.
* The first macOS build is ad-hoc signed but not Developer ID signed or notarized.
  After verification, use Finder's Control-click "Open" or Privacy & Security's
  per-file "Open Anyway" only when device policy permits it; otherwise use uv.
  Never disable SmartScreen or Gatekeeper globally or remove quarantine metadata.

Verify the download
-------------------

The GitHub Release includes a `.sha256` file beside each archive. On Linux, run
`sha256sum -c ARCHIVE.sha256`; on macOS, run
`shasum -a 256 -c ARCHIVE.sha256`. On Windows PowerShell, compare
`(Get-FileHash ARCHIVE -Algorithm SHA256).Hash` with the value in the `.sha256`
file. A checksum detects corruption. With GitHub CLI installed, run
`gh attestation verify @ARCHIVE@ --repo jasonzhang06-source/sharelint` beside the
downloaded archive. The attestation associates those exact bytes with this
repository's workflow identity; it is not code signing, a reproducible-build
proof, or a safety verdict.

Files in this folder
--------------------

* @EXECUTABLE@ — ShareLint
* BUILD-INFO.json — format-version 2 transparency record containing the target,
  tool versions, lock and executable digests, each frozen native file's name,
  size, SHA-256, and CArchive typecode, the target's reviewed static-component
  evidence, and equal digests of PyInstaller's canonical Analysis and PKG
  name/type inventories
* LICENSE.txt — ShareLint MIT license
* PYTHON-LICENSE.txt — license shipped with the embedded Python runtime
* PYINSTALLER-LICENSE.txt — freezer license and bootloader exception
* THIRD-PARTY-NOTICES.txt — reviewed notices for the CPython and native-library
  components mapped by the repository's format-version 2 native-license catalog

The native build gate refuses to create an archive if a frozen native file is
unknown, the Analysis and PKG name/type digests differ, either name inventory
differs from the CArchive, a recorded file identity is malformed or no longer
matches the executable, a required static component is not accounted for, or
the corresponding notice is missing. Native file records use typecode `b`.
Keep every license and notice file with redistributed copies of the executable.
BUILD-INFO.json and the notice gate improve auditability; they are not an
independent trust root, a complete SBOM, legal certification, or proof that the
executable can be reproduced byte for byte.

Project: https://github.com/jasonzhang06-source/sharelint
