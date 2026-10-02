# ShareLint 3.0 compatibility review

Version 3 introduces a new capability: creating a reviewed, freshly scanned text
derivative. It does **not** turn existing scans into transformations. No existing
command modifies originals, and there is no implicit cleanup, in-place option,
or weakening of the existing pack gate.

Existing command syntax, Python exports, exit codes, native report schema
`1.0.0`, pack receipt schema `2.0.0`, and handoff/batch contracts remain available.
The new `redact` family has distinct plan and receipt types, each at schema
`1.0.0`; do not send a redaction receipt to a ZIP-receipt consumer. See
[text derivatives](redaction.md) for the full contract and strict limitations.

Text detection now exposes internal match positions shared by scanning and
redaction. Existing detector order, masking, report-local fingerprints, and
coverage behavior are retained and regression-tested. Those internal modules
are not part of the stable public Python API.

As with earlier handoff plans, packing/application of a plan made by an older
producer requires recreating and reviewing the plan. Historical plan/receipt
verification is separate and does not require the original source to be present.

The new write surface is explicitly invoked by `redact apply`. It requires all
source/output coverage and **zero remaining known output findings**, including
below-threshold ones. It is stricter than a regular scan threshold and does not
prove that the output contains no undetected sensitive material.
