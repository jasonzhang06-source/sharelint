# ShareLint compatibility and migration

Version 1.0 stabilizes the existing local privacy preflight. It does not expand
format coverage or turn a passing scan into a guarantee of safe sharing.

Version 2.0 adds explicit policy profiles, offline verification, aggregate report
comparison, and optional handoff plans. It changes all newly emitted receipt
manifests to schema `2.0.0`: entry indices replace raw paths. Legacy receipts
remain readable. See [migration](migration-2.md) before updating machine consumers.

Version 3.0 adds explicit, reviewed text derivatives with separate redaction
plan/receipt contracts. Existing commands and schemas remain supported; scanning
never implicitly transforms a source. Read the [3.0 compatibility review](migration-3.md).

## Supported contracts

- Python 3.11 and newer; native CI covers the versions listed in
  [platform support](platform-support.md).
- Existing `scan`, `pack`, `demo`, `rules`, and `explain` commands and options,
  plus `config`, `verify`, `diff`, and `plan` workflows.
- Exit codes: `0` for a completed, non-blocking command, `1` for a policy block,
  and `2` for usage or operational errors. `demo` returns `0` for its deliberately
  blocked synthetic example. Use `scan --strict` to fail on incomplete coverage.
- Native report schema `1.0.0`, receipt schema `2.0.0`, and SARIF 2.1.0, as specified in
  [report formats](report-format.md). Package and schema versions are independent.
- Public Python exports listed in `sharelint.__all__`; underscore-prefixed
  functions and scanner implementation modules are internal.

Compatible releases retain existing documented commands and required output
fields. A breaking change to those interfaces requires a new major package
version. Follow each schema's own versioning and unknown-field rules when
consuming machine output. Console and HTML presentation may improve in patches;
automation should use JSON or SARIF.

## Detection and security updates

In 2.0, user cancellation returns `130` with a concise diagnostic. Failed
output pipes return `2`, including buffered help/version output. Cancellation
does not claim that no files exist: a completed publication may precede the
interrupt. Review outputs before retrying; no-overwrite rules still apply.

Rules, severity classifications, and coverage checks may become stricter in a
patch when correcting a detection or security defect. Consequently, the same
input can produce new findings or a blocked result after an upgrade. Changes
are recorded in the changelog. Pin the package version for repeatable automation
and review updates before changing it.

The latest released version and default branch receive fixes, under the
[security policy](../SECURITY.md). No fixed multi-year support period or
response-time guarantee is offered. Releases and their files are never replaced;
corrections receive a new patch version.

## Coverage retained in 3.0

PDF inspection remains static, image inspection remains metadata-only, and
there is no OCR or graphical interface. The original scan and pack commands do
not clean files; 3.0 adds a separate bounded [text-derivative workflow](redaction.md).
The [offline receipt verifier](verification.md) checks integrity and consistency;
it does not rescan content. Unsupported content stays visible as incomplete coverage and blocks
`pack`. Scanning does not upload data or modify originals. Reports can still
reveal contextual filenames and structure and should be handled accordingly.
