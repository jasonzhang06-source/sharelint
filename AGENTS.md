# ShareLint contributor instructions

ShareLint is a local-only privacy preflight tool. Preserve these invariants:

- Never send scanned content, findings, filenames, or telemetry over a network.
- Never include raw matched evidence in reports, logs, exceptions, or tests.
- Never extract untrusted archives to disk. Inspect members through bounded streams.
- Treat incomplete coverage, parser errors, encrypted members, and exhausted budgets
  as explicit coverage gaps. Never turn them into a clean verdict.
- Keep the default runtime dependency-free and compatible with Python 3.11+.
- Use only synthetic identities, credentials, and documents in tests and examples.
- Add or update tests for every rule, parser, limit, output contract, and exit-code change.
- User-visible claims must say what was checked; do not claim that a file is safe or
  free of all sensitive data.

Run before submitting changes:

```bash
python -m unittest discover -s tests -v
PYTHONPATH=src python -m sharelint demo
python -m compileall -q src tests
```
