## Summary

<!-- What changed, and why is it needed? -->

## Related issue

<!-- Link an issue when applicable, for example: Closes #123 -->

## Validation

<!-- List the exact commands and results used to verify this change. -->

```text
python -m unittest discover -s tests -v
PYTHONPATH=src python -m sharelint demo
python -m compileall -q src tests
ruff check .
ruff format --check .
mypy
```

## Privacy and maintenance checklist

- [ ] Tests use only clearly synthetic data.
- [ ] Normal reports, logs, errors, and snapshots do not expose matched values.
- [ ] New or changed parsers have bounded input and explicit unknown/error behavior.
- [ ] Originals remain untouched unless the behavior is explicit and documented.
- [ ] No scanning-path network behavior was added.
- [ ] User-facing behavior and known blind spots are documented.
- [ ] English and Chinese user-facing docs were updated together, or the difference is explained above.
- [ ] Tests and quality checks pass, or exceptions are explained above.
- [ ] The change is focused enough to maintain over time.

## Risk notes

<!-- Describe compatibility, security, privacy, performance, or migration risks. -->
