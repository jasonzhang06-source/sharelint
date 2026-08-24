# Releasing ShareLint

This checklist keeps GitHub, PyPI, source metadata, and the published package aligned. PyPI
versions and release tags are immutable records: never reuse a version or move a published tag.

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

## Prepare a release

1. Update `src/sharelint/_version.py` and move the release notes from `Unreleased` into a dated
   section in `CHANGELOG.md`.
2. Confirm that schema identifiers, package metadata, documentation, and examples describe the
   same version.
3. Run the complete local gate from the repository root:

   ```bash
   python -m unittest discover -s tests -v
   PYTHONPATH=src python -m sharelint demo
   python -m compileall -q src tests
   ruff check .
   ruff format --check .
   mypy
   PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 pytest -p pytest_cov.plugin --cov=sharelint --cov-branch -q
   python -m build
   python -m twine check dist/*
   ```

4. Push the release commit and wait for both CI and CodeQL to succeed on `main`.
5. Create and push an annotated tag that exactly matches the package version:

   ```bash
   sharelint_version=0.1.1
   git tag -a "v${sharelint_version}" -m "ShareLint ${sharelint_version}"
   git push origin "v${sharelint_version}"
   ```

   Set `sharelint_version` to the version being released. Never tag an unverified commit.

## Publish and verify

1. Draft a GitHub Release from the existing tag. Use the matching changelog section as the release
   notes and mark unstable versions as a prerelease.
2. Publish the GitHub Release. This triggers `.github/workflows/release.yml`, which rebuilds and
   verifies the distributions before publishing them to PyPI through OIDC.
3. Confirm that the release workflow succeeded and that PyPI shows verified project links and
   provenance.
4. Install from PyPI in a new virtual environment and smoke-test the public commands:

   ```bash
   sharelint_version=0.1.1
   python -m venv /tmp/sharelint-release-check
   /tmp/sharelint-release-check/bin/python -m pip install --no-cache-dir "sharelint==${sharelint_version}"
   /tmp/sharelint-release-check/bin/sharelint --version
   /tmp/sharelint-release-check/bin/sharelint rules
   /tmp/sharelint-release-check/bin/sharelint demo
   ```

If a published package is materially broken, publish a corrected patch version. Yank the broken
PyPI release when necessary; do not replace its files or retarget its Git tag.
