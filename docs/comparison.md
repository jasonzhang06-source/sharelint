# Compare two native scan reports

ShareLint 1.3 compares **aggregate rule/severity counts**, not the original
matched values. The comparison is entirely local and uses validated native JSON
reports. SARIF and HTML scan reports are not accepted as comparison inputs.

```sh
sharelint scan ./handoff-before --format json -o before.json
sharelint scan ./handoff-after --format json -o after.json
sharelint diff before.json after.json
sharelint diff before.json after.json --format json
sharelint diff before.json after.json --format html -o comparison.html
```

Output files must be new. An HTML comparison is self-contained, has no scripts
or external resources, and must be written with `-o`.

## Read the result conservatively

Each changed rule/severity bucket shows its old count, new count, and signed
delta. A reduced count is **not** a claim that a particular secret was removed.
One finding can disappear while a different finding appears in the same bucket.
Report-scoped HMAC fingerprints cannot establish cross-scan evidence identity;
the comparison never uses them as stable identifiers.

| Decision | Exit | Meaning |
| --- | --- | --- |
| `no-regression-observed` | `0` | No blocking-count increase or stated review condition was observed |
| `regression-observed` | `1` | A blocking rule/severity count or coverage gap count increased |
| `review-required` | `1` | Changed settings, incomplete/empty coverage, or reduced inspection needs review |
| Invalid input | `2` | A document could not be safely read or validated |

An unchanged report can still have existing blockers. Exit `0` is not a passing
privacy scan, proof of equivalence, or authorization to share. Check the current
scan result and use the independent strict `pack` gate before delivery.

Reduced surface or inspected-byte counts need review even if every remaining
surface is marked scanned. Files might have been omitted, although a legitimate
edit can also reduce these counts. Existing incomplete coverage always needs
review. Unknown coverage states and inconsistent summaries are rejected.

Producer version, resource limits, target kind, and recorded threshold changes
are shown as fixed review reasons. To compare both reports under an explicit
common blocking threshold, pass `--fail-on medium` (or another severity); other
settings changes still require review. This does not rerun either scan.

## Privacy and input boundaries

Comparison output contains fixed labels, counts, and SHA-256 digests of its two
input reports. It does not echo imported paths, titles, locations, previews,
remediations, error messages, or producer-provided claims. Unknown rule IDs are
grouped under `unrecognized-rule`, preserve their severities/counts, and always
require review. Never treat an unknown ID as an ignored finding.

Both inputs use the [bounded JSON and file-read contract](verification.md#limits-and-exit-codes).
No filenames from inside a report are followed. Comparison digests and counts
still provide context, so share the output only with appropriate recipients.

The `sharelint.aggregate-diff` JSON envelope has its own schema version `1.0.0`;
it is not a native scan report or a pack receipt. Native scan/receipt contracts
and existing command behavior are unchanged.
