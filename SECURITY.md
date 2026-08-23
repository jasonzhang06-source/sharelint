# Security Policy

## Supported versions

Security fixes are applied to the latest released version and the default
branch. Older releases may not receive backports.

| Version | Supported |
| --- | --- |
| Latest release | Yes |
| Default branch | Yes |
| Older releases | No |

## Reporting a vulnerability

Use this repository's **Security** tab and select **Report a vulnerability** to
open a private GitHub security advisory. Do not open a public issue or pull
request for a suspected vulnerability.

Please include:

- the affected version or commit;
- the security impact and affected trust boundary;
- minimal reproduction steps using synthetic data;
- relevant configuration and platform details;
- any suggested mitigation.

Do not submit real secrets, personal information, confidential documents, or
unredacted scanner output. Replace sensitive values with synthetic equivalents
that preserve the relevant structure.

The maintainer aims to acknowledge reports within seven days. Investigation and
release timing depend on severity, reproducibility, and maintainer capacity.
Please allow time for coordinated remediation before public disclosure.

## Security-relevant examples

Private reporting is appropriate for issues such as:

- sensitive values appearing in default reports, logs, errors, temporary
  files, or receipts;
- path traversal, unsafe archive extraction, decompression bombs, or unbounded
  resource consumption;
- unexpected network transmission during local scanning;
- a remediation that leaves supposedly removed content recoverable;
- bypasses of documented fail-closed behavior;
- materially misleading coverage or verification results.

Ordinary false positives, feature requests, and non-sensitive crashes can use a
public issue. When unsure, report privately.

ShareLint reduces disclosure risk; it cannot guarantee anonymity, legal
compliance, or detection of every sensitive value.
