# Releasing ShareLint

This checklist keeps GitHub, PyPI, source metadata, Python distributions, and
native standalone assets aligned. PyPI versions, release tags, and attached
release assets are immutable records: never reuse a version, move a published
tag, or replace a published file.

## One-time trusted publishing setup

ShareLint publishes with PyPI Trusted Publishing, not a long-lived API token.

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
must have typecode `b`. This is a transparency record inside the checksummed and
attested archive—not an independent trust root, complete SBOM, legal
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

Release `v0.1.2` and earlier do not have these standalone assets. The four
native outputs and their license inventories still require a complete CI run
for the next tagged release. Do not document an asset as downloadable until it
is visibly attached to a completed GitHub Release.

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

## Prepare a release

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

## Publish and verify

1. Pushing the annotated `v*` tag triggers `.github/workflows/release.yml`.
   Do not manually publish a Release for that tag. The workflow first creates
   or reuses an unpublished draft, then:

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

   A failure leaves the GitHub Release private and stops the remaining jobs.
   Diagnose or rerun the failed workflow instead of publishing the draft or
   replacing an asset manually.
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
- `actions/attest@v4` records GitHub build provenance for the exact release
  bytes. It does not prove the program is safe or make the build reproducible.
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
