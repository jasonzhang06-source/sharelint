# Releasing ShareLint

## Current manual publication policy

The current GitHub and PyPI release is [ShareLint 3.0.0](https://github.com/jasonzhang06-source/sharelint/releases/tag/v3.0.0).
The release was published manually by `jasonzhang06-source`; the PyPI upload was
made from the maintainer's `Jason_Zhang111` account with a project-scoped token.
The `Publish release` workflow is disabled in GitHub Actions. Keep it disabled:
the project must not silently publish from a tag or impersonate a bot.

The v3.0.0 GitHub release contains one verified Python wheel,
`sharelint-3.0.0-1-py3-none-any.whl`, with SHA-256
`b84ef05cd4a46e99823e4d5d45d6ee721550490f0839fa7661b6cc7bb9564313`.
It is a wheel-only release; the verified native Linux, Windows, and macOS
archives remain attached to v2.0.0 until a separately reviewed native build is
made. Do not invent v3 native download URLs.

To manage this release manually:

1. Sign in as `jasonzhang06-source` and use the repository's **Releases** page.
2. Select the existing, verified `v3.0.0` tag and confirm the exact commit.
3. Create the draft while signed in to that account and confirm the author is
   `jasonzhang06-source`, then click **Publish release** yourself.
4. Separately upload the single wheel to PyPI as `Jason_Zhang111`; do not use
   Trusted Publishing or store the token in the repository.
5. Review the public author, version, asset filename, digest, and installation
   result after each publication.

Run source checks and CI independently of publication. A successful CI run
validates the tested commit; it does not authorize or perform publication.
Pushing documentation to `main` does not create a release or upload a package.

## PyPI 3.0.0 build 1

Published on **2026-10-02 (Asia/Shanghai)** from the maintainer account.
The public file is [sharelint-3.0.0-1-py3-none-any.whl](https://pypi.org/project/sharelint/3.0.0/)
and its public download matched the recorded digest above. The wheel reports
`ShareLint 3.0.0`; a fresh isolated installation and demo smoke test passed.

## Historical PyPI 2.0.0 build 1

Published on **2026-09-21 (Asia/Shanghai)**, separately from the GitHub
republication on 2026-09-14. The upload was accepted at
`2026-09-20T16:21:23Z` (UTC).

[PyPI 2.0.0](https://pypi.org/project/sharelint/2.0.0/) provides
`sharelint-2.0.0-1-py3-none-any.whl`, published through the maintainer's
`Jason_Zhang111` PyPI account. The package version remains `2.0.0`; `1` is a
standard wheel build tag, not a new software version or an intermediate release.

The original PyPI 2.0.0 files were deleted and their filenames cannot be reused.
The old wheel and sdist are not restored. This publication adds only the new
wheel filename and no new sdist. Use the preserved GitHub `v2.0.0` source tag
if a source installation is needed.

The wheel retains the original runtime code. Its package description is corrected
for the current release, its `WHEEL` metadata records `Build: 1`, and `RECORD`
is regenerated for the resulting contents. This is a metadata-only wheel rebuild,
not the original wheel renamed, and does not import later development changes.
The GitHub tag and all eight native archive/checksum files remain unchanged.

The published wheel's SHA-256 is
`3a310738e96e24ddb48a100ce3e31aac08ae470814d49889a986ccd4dadee51a`.
Its public download was compared byte-for-byte with the validated local wheel.
An isolated installation from the public PyPI index selected version `2.0.0`
and build `1`; version, demo, and dependency checks passed.

Keep the original and new package hashes and metadata, the runtime-file
comparison, package checks, upload result, and public-download installation
checks together as publication evidence. Never store a PyPI token in the
repository or publication logs. CI results are separate from the identity
and authorization used to publish.

Historical 2.0 Python installation guidance selected `sharelint==2.0.0`; the
current guidance above selects 3.0.0. GitHub native downloads and the fixed
`git+https://github.com/jasonzhang06-source/sharelint.git@v2.0.0` source remain
the historical native alternatives.

See the [wheel build-tag specification](https://packaging.python.org/en/latest/specifications/binary-distribution-format/)
and [PyPI filename-reuse policy](https://pypi.org/help/#file-name-reuse).

## Build and automated-pipeline reference (inactive)

The sections below document the existing build contracts and the pipeline used
to produce the original native artifacts. They are not instructions to enable
or run the currently disabled publishing workflow, recreate the 2.0.0 tag, or
repeat its PyPI upload.

This checklist keeps GitHub, PyPI, source metadata, Python distributions, and
native standalone assets aligned. PyPI versions, release tags, and attached
release assets are immutable records: never use a published version for changed
runtime code, move a published tag, or replace a published file. The documented
2.0.0 metadata-only build above does not permit replacing files or changing
runtime code.

## Historical trusted publishing setup (inactive)

The original pipeline used PyPI Trusted Publishing, not a long-lived API token.

1. In the GitHub repository, create an environment named `pypi` under
   **Settings → Environments**. Add a required reviewer when the account and plan support it.
2. In the PyPI account's **Publishing** page, add a pending GitHub publisher with these exact
   values:

   | Field | Value |
   | --- | --- |
   | PyPI project name | `sharelint` |
   | Owner | `jasonzhang06-source` |
   | Repository | `sharelint` |
   | Workflow | `release.yml` |
   | Environment | `pypi` |

The pending publisher creates the PyPI project on its first successful use. It does not reserve
the name beforehand. See the
[PyPI pending publisher guide](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/)
and [trusted publishing security model](https://docs.pypi.org/trusted-publishers/security-model/).

## Standalone asset contract

The release workflow builds on native GitHub-hosted runners; these executables
are not cross-compiled. The first configured matrix is:

| Runner | Target | Archive |
| --- | --- | --- |
| `ubuntu-22.04` | `linux-glibc-x86_64` | `sharelint-v{version}-linux-glibc-x86_64.tar.gz` |
| `windows-2022` | `windows-x86_64` | `sharelint-v{version}-windows-x86_64.zip` |
| `macos-15-intel` | `macos-x86_64` | `sharelint-v{version}-macos-x86_64.tar.gz` |
| `macos-15` | `macos-arm64` | `sharelint-v{version}-macos-arm64.tar.gz` |

`{version}` is the package version without the leading `v`. Every archive has
a same-named `.sha256` file. Its only members are stored beneath a top-level
directory whose name is the archive name without `.tar.gz` or `.zip`:

- `sharelint` (`sharelint.exe` on Windows), mode `0755`;
- `BUILD-INFO.json`, mode `0644`;
- `README.txt`, mode `0644`;
- `LICENSE.txt`, mode `0644`;
- `PYTHON-LICENSE.txt`, mode `0644`;
- `PYINSTALLER-LICENSE.txt`, mode `0644`;
- `THIRD-PARTY-NOTICES.txt`, mode `0644`.

The workflow rejects missing, extra, corrupt, incorrectly named, non-canonical,
or trailing archive data and checks the recorded modes and byte bindings.
Format-version 2 of `BUILD-INFO.json` records the target, selected
build-component versions, lock-file and executable digests, target-specific
static-component evidence, and the exact `THIRD-PARTY-NOTICES.txt` digest. Its
`native_runtime.files` value is a canonical list of objects whose only fields
are `name`, `size`, `sha256`, and `typecode`; every recorded CArchive native file
must have typecode `b`. This is a transparency record inside the checksummed
archive—not an independent trust root, complete SBOM, legal
certification, or reproducible-build proof.

Every native target must reconcile the executable's CArchive entries with its
Analysis and PKG inventories. `analysis_inventory_sha256` and
`package_inventory_sha256` are SHA-256 summaries of canonical `{name, type}`
records; both summaries must be equal, and both name lists must equal the final
CArchive native-file list. Each dynamic native file and each reviewed
target-specific static component must map to the pinned format-version 2
native-license catalog and to notice text included in
`THIRD-PARTY-NOTICES.txt`. Unknown, malformed, cross-stage-inconsistent, or
uncovered entries fail the target before upload. The aggregate job then
requires all four independently built target archives to pass the same
contract.

The current static rules deliberately include:

- mimalloc 2.1.2 unconditionally for the Linux and Windows CPython cores;
- two independent unconditional Windows zlib records: PyInstaller bootloader
  1.3.2 and CPython core 1.3.1; and
- SQLite 3.50.4 for both macOS targets when `_sqlite3*.so` is present.

The catalog contains additional matched components. Update it and the notice
source only after inspecting a real native build; never add a wildcard merely
to make CI green.

Release `v0.1.2` and earlier do not have these standalone assets. A newly built
native output and its license inventory require native CI validation. The
2.0.0 restoration reuses the original archives rather than rebuilding them.
Do not document an asset as downloadable until it is visibly attached to a
completed GitHub Release.

## Source distribution normalization contract

The release build runs `scripts/normalize_sdist.py` after setuptools creates the
source distribution, and the separate distribution-verification job runs it
again with `--check`. The normalizer requires the expected project/version root,
bounded regular files and directories only, unique safe POSIX member names, and
no hidden gzip or tar data. It writes sorted USTAR members with zero timestamps,
UID and GID, empty owner names, `0755` directories, and `0644` files except for
files whose executable bit was already set. The gzip stream uses an empty name,
maximum compression, and timestamp zero.

Two valid inputs with identical member names, contents, and executable-bit
choices therefore normalize to the same bytes under the locked release
toolchain. This deliberately narrow guarantee does not make generated content,
the wheel, the four native executables, or the mutable runner OS reproducible.
If normalization or the independent byte check fails, stop the release; do not
upload the pre-normalized sdist or bypass the check.

## Historical new-version preparation checklist (inactive)

This checklist applies to creating a new version, not restoring 2.0.0. The
current manual publication policy above takes precedence. None of the steps
below authorize a new tag, package version, or publication.

1. Update `src/sharelint/_version.py` and move the release notes from `Unreleased` into a dated
   section in `CHANGELOG.md`.
2. Confirm that schema identifiers, package metadata, documentation, and examples describe the
   same version.
3. Run the complete Python-package gate from the repository root:

   ```bash
   python -m unittest discover -s tests -v
   PYTHONPATH=src python -m sharelint demo
   python -m compileall -q src tests
   ruff check .
   ruff format --check .
   mypy
   PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 pytest -p pytest_cov.plugin --cov=sharelint --cov-branch -q
   ```

4. When changing the standalone builder or packaging contract, build and test
   the executable for the maintainer's current host in a fresh output directory:

   ```bash
   python3.13 -c 'import platform; assert platform.python_version() == "3.13.15"'
   portable_check_root="$(mktemp -d)"
   python3.13 -m venv "$portable_check_root/venv"
   "$portable_check_root/venv/bin/python" -m pip install \
     --require-hashes --only-binary=:all: -r requirements/standalone-build.txt
   "$portable_check_root/venv/bin/python" -m build --wheel --no-isolation \
     --outdir "$portable_check_root/dist"
   "$portable_check_root/venv/bin/python" -m pip install \
     --force-reinstall --no-deps "$portable_check_root"/dist/*.whl
   "$portable_check_root/venv/bin/python" scripts/build_portable.py \
     --output-dir "$portable_check_root/output"
   "$portable_check_root/venv/bin/python" scripts/verify_portable.py \
     "$portable_check_root/output/sharelint"
   portable_version="$("$portable_check_root/venv/bin/python" -c \
     'import importlib.metadata; print(importlib.metadata.version("sharelint"))')"
   portable_target="$("$portable_check_root/venv/bin/python" -c \
     'from scripts.build_portable import detect_target; print(detect_target().slug)')"
   "$portable_check_root/venv/bin/python" scripts/verify_release_assets.py \
     "$portable_check_root/output" --version "$portable_version" \
     --target "$portable_target" --executable "$portable_check_root/output/sharelint"
   ```

   Building and installing the wheel before freezing prevents an editable source
   checkout from silently becoming the release payload. The release inputs lock
   Python to CPython 3.13.15 and lock every pip build/freezer wheel by SHA-256;
   they do not make the mutable runner OS or native toolchain hermetic or the
   resulting executable reproducible. On Windows, use `Scripts\\python.exe`,
   pass `sharelint.exe`, and use the `windows-x86_64` target. A local build
   validates only its current native target; it does not replace the four
   required CI jobs.
5. Push the release commit and wait for CI and CodeQL to succeed on `main`,
   including all four portable jobs.
6. Create and push an annotated tag that exactly matches the package version:

   ```bash
   sharelint_version="$(PYTHONPATH=src python -c 'import sharelint; print(sharelint.__version__)')"
   git tag -a "v${sharelint_version}" -m "ShareLint ${sharelint_version}"
   git push origin "v${sharelint_version}"
   ```

   Set `sharelint_version` to the version being released. Never tag an unverified commit.

## Historical automated publication and verification

1. When enabled, `.github/workflows/release.yml` responds to an annotated `v*`
   tag. It is currently disabled; the manual policy above applies. The historical
   workflow first creates or reuses an unpublished draft, then:

   - re-runs the source checks and builds the Python distributions;
   - normalizes the sdist and independently checks its canonical bytes;
   - builds and smoke-tests all four native `onefile` executables;
   - fails each native target if its Analysis/PKG inventory, native hashes,
     static-component evidence, or required third-party notice is incomplete;
   - verifies the exact eight-file archive/checksum set and archive contents;
   - requests GitHub artifact attestations for those eight files;
   - uploads each asset idempotently, accepting an existing draft asset only
     when its SHA-256 matches exactly;
   - publishes to PyPI through OIDC only after the portable assets are attached;
     and
   - makes the draft public only after PyPI succeeds.

   In that historical flow, a failure left the GitHub Release private and
   stopped the remaining jobs. It is not the procedure for this manual
   restoration: the publishing workflow remains disabled.
2. Confirm that the release workflow succeeded, all eight standalone files are
   visible on the Release page, and PyPI shows the expected version and verified
   project links.
3. Download a native archive and its checksum from the Release—not from a normal
   CI artifact—and verify both checksum and GitHub build provenance. For example:

   ```bash
   gh release download "v${sharelint_version}" \
     --repo jasonzhang06-source/sharelint \
     --pattern "sharelint-v${sharelint_version}-linux-glibc-x86_64.tar.gz*"
   sha256sum --check \
     "sharelint-v${sharelint_version}-linux-glibc-x86_64.tar.gz.sha256"
   gh attestation verify \
     "sharelint-v${sharelint_version}-linux-glibc-x86_64.tar.gz" \
     --repo jasonzhang06-source/sharelint
   ```

   Then extract it in a clean directory and run `./sharelint --version`,
   `./sharelint rules`, and `./sharelint demo`. Repeat or delegate this check for
   the other native targets when practical.
4. Install from PyPI in a new virtual environment and smoke-test the public
   commands:

   ```bash
   release_check_root="$(mktemp -d)"
   python -m venv "$release_check_root/venv"
   "$release_check_root/venv/bin/python" -m pip install --no-cache-dir \
     "sharelint==${sharelint_version}"
   "$release_check_root/venv/bin/sharelint" --version
   "$release_check_root/venv/bin/sharelint" rules
   "$release_check_root/venv/bin/sharelint" demo
   ```

5. Only after the release assets are verified should documentation on `main`
   change their status from forthcoming to available. Do not rewrite the docs in
   the already-published tag.

## Integrity, provenance, and signing status

Keep these claims separate in release notes and support responses:

- A `.sha256` file detects a mismatch with the checksum the user obtained. It
  does not identify the publisher if both files can be replaced.
- When hosted attestations exist, `actions/attest@v4` records GitHub build
  provenance for exact release bytes. Previous attestations were removed and
  are not restored by the 2.0.0 republication. Build provenance would not prove
  the program is safe or make the build reproducible.
- The first Windows standalone line has no Authenticode signature. SmartScreen
  may report an unrecognized publisher.
- The first macOS standalone line uses PyInstaller's ad-hoc signing only. It has
  no Developer ID distribution signature and is not Apple-notarized.

Do not describe checksums or attestations as platform code signing. Update the
signing claims only after the corresponding signing/notarization step is present
in the workflow and a published asset has been verified.

If a published package is materially broken, publish a corrected patch version. Yank the broken
PyPI release when necessary; do not replace its files, overwrite GitHub assets,
or retarget its Git tag.
