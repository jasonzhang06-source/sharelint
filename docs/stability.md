# ShareLint 1.x compatibility

Version 1.0 stabilizes the existing local privacy preflight. It does not expand
format coverage or turn a passing scan into a guarantee of safe sharing.

## Supported contracts

- Python 3.11 and newer; native CI covers the versions listed in
  [platform support](platform-support.md).
- Existing `scan`, `pack`, `demo`, `rules`, and `explain` commands and options.
- Exit codes: `0` for a completed, non-blocking command, `1` for a policy block,
  and `2` for usage or operational errors. `demo` returns `0` for its deliberately
  blocked synthetic example. Use `scan --strict` to fail on incomplete coverage.
- Native report and receipt schema `1.0.0`, and SARIF 2.1.0, as specified in
  [report formats](report-format.md). Package and schema versions are independent.
- Public Python exports listed in `sharelint.__all__`; underscore-prefixed
  functions and scanner implementation modules are internal.

Compatible releases retain existing documented commands and required output
fields. A breaking change to those interfaces requires a new major package
version. Follow each schema's own versioning and unknown-field rules when
consuming machine output. Console and HTML presentation may improve in patches;
automation should use JSON or SARIF.

## Detection and security updates

Rules, severity classifications, and coverage checks may become stricter in a
patch when correcting a detection or security defect. Consequently, the same
input can produce new findings or a blocked result after an upgrade. Changes
are recorded in the changelog. Pin the package version for repeatable automation
and review updates before changing it.

The latest released version and default branch receive fixes, under the
[security policy](../SECURITY.md). No fixed multi-year support period or
response-time guarantee is offered. Releases and their files are never replaced;
corrections receive a new patch version.

## Coverage retained in 1.0

PDF inspection remains static, image inspection remains metadata-only, and
there is no OCR, automatic cleaning, graphical interface, or receipt verification
command. Unsupported content stays visible as incomplete coverage and blocks
`pack`. Scanning does not upload data or modify originals. Reports can still
reveal contextual filenames and structure and should be handled accordingly.
