# Contributing to ShareLint

Thanks for helping make ShareLint more useful and trustworthy. Small, focused
changes with tests are easiest to review and maintain.

## Before opening an issue

- Search existing issues and the roadmap for related work.
- Use a minimal synthetic example. Never upload real credentials, personal
  information, client documents, or other confidential material.
- Report possible vulnerabilities privately as described in
  [SECURITY.md](SECURITY.md), not in a public issue.

## Development workflow

1. Fork the repository and create a branch from `main`.
2. Create a virtual environment and install the development dependencies:

   ```bash
   python -m venv .venv
   source .venv/bin/activate
   python -m pip install -e ".[dev]"
   ```

3. Make one coherent change and add or update tests.
4. Run the required repository checks:

   ```bash
   python -m unittest discover -s tests -v
   PYTHONPATH=src python -m sharelint demo
   python -m compileall -q src tests
   ```

   When the development extras are installed, also run:

   ```bash
   ruff check .
   ruff format --check .
   mypy
   PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 pytest -p pytest_cov.plugin --cov=sharelint --cov-branch -q
   ```

5. Open a pull request using the repository template.

If a command is not available on the branch you are contributing to, explain
what you ran instead in the pull request.

## Privacy and safety expectations

ShareLint operates on potentially sensitive files. Contributions must:

- keep test fixtures synthetic and clearly fictional;
- hide matched values in normal reports, logs, exceptions, and snapshots;
- treat unknown, encrypted, truncated, or unscanned content explicitly rather
  than silently declaring it clean;
- bound recursion, decompression, file sizes, and other attacker-controlled
  work;
- preserve originals unless an explicitly documented command says otherwise;
- never send scanned content, findings, filenames, or telemetry over a
  network;
- describe results as policy and coverage findings, not as a guarantee that a
  file is anonymous or safe.

New scanners should document supported surfaces, known blind spots, resource
limits, and stable finding identifiers. Include nominal, malformed-input, and
false-positive regression tests where practical.

Rule changes should also follow the checklist in
[Adding or changing a rule](docs/rules.md#adding-or-changing-a-rule).

## Pull request review

The maintainer may ask for changes to scope, tests, privacy behavior, or public
interfaces. A pull request can be declined when its ongoing maintenance cost is
too high, even if the implementation works. Decisions and material tradeoffs
should remain visible in the issue or pull request.

By contributing, you agree that your contribution is licensed under the
project's MIT License.
