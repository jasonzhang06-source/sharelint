# ShareLint documentation

Use this page as the stable map of ShareLint's user, integration, contributor,
and maintainer documentation for ShareLint 1.0.0. Documented
coverage is a measured boundary, not a guarantee that a file is safe or free of
sensitive data.

Current release: [ShareLint 1.0.0](https://github.com/jasonzhang06-source/sharelint/releases/tag/v1.0.0).
Use the version-pinned installation commands in the quick start.

## Use ShareLint

- [Quick start and command examples](../README.md#quick-start)
- [Installation and troubleshooting](troubleshooting.md)
- [Platform support and filesystem requirements](platform-support.md)
- [What ShareLint checks](../README.md#what-it-checks)
- [Rules and stable identifiers](rules.md)
- [Project direction and non-goals](roadmap.md)

## Integrate reports

- [Native JSON, SARIF, and receipt contracts](report-format.md)
- [Native report JSON Schema](../schemas/report.schema.json)
- [Pack receipt JSON Schema](../schemas/receipt.schema.json)

Machine consumers should prefer the native JSON report when they need complete
ShareLint coverage semantics. SARIF is an integration projection, and a pack
receipt is an integrity summary bound to a separate native report.

## Contribute safely

- [Contributor workflow](../CONTRIBUTING.md)
- [Architecture and extension points](architecture.md)
- [Rule contribution checklist](rules.md#adding-or-changing-a-rule)
- [Threat model and required controls](threat-model.md)
- [Code of Conduct](../CODE_OF_CONDUCT.md)

All fixtures and examples must be synthetic. Never attach a real secret,
personal document, client file, or unsanitized ShareLint report to a public
issue or pull request.

## Maintain and release

- [Release process](releasing.md)
- [Security policy](../SECURITY.md)
- [Support policy](../SUPPORT.md)
- [Governance](../GOVERNANCE.md)
- [Changelog](../CHANGELOG.md)
- [1.x compatibility and maintenance](stability.md)

Possible vulnerabilities belong in GitHub's private vulnerability reporting
flow, not in a public issue.
