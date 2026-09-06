# Review a handoff before packing it

ShareLint 2.0 adds a local, reviewable snapshot of one selected source and its
effective packing policy. A plan is not a signature, authorization token, or
permission to bypass a scan. No data leaves your machine.

```bash
sharelint plan create ./handoff -o handoff.plan.json
sharelint plan inspect handoff.plan.json
sharelint pack ./handoff -o delivery.zip --plan handoff.plan.json
sharelint verify delivery.zip --receipt delivery.zip.sharelint.json --report delivery.zip.sharelint.report.json --plan handoff.plan.json
```

Use new output paths outside the selected input directory. Existing files are
never overwritten. A plan contains a masked native report and must still be
kept private: document structure, counts, and contextual names can identify a
handoff. `plan inspect --format json` emits aggregates and digests, not imported
report text. Inspecting a plan does not rescan its source.

## What is bound

- Selected source basename, kind, and content/tree digest, without recording an
  absolute path. Moving identical content under the same basename is allowed;
  renaming the boundary requires a new plan.
- Effective limits, threshold, complete-coverage requirement, and ruleset hash.
- Producer version and the masked report structure. Report-local random HMACs
  are deliberately excluded from snapshot comparison; they are never durable
  matched-value identities.

`pack --plan` scans again and compares these bindings both before building and
after its final source recheck. It also performs the normal artifact rescan,
manifest comparison, and non-overwriting publication. Source, policy, result,
or producer-version changes require a new plan and review. A blocked plan cannot
authorize a pack. The plan is bound to the exact receipt by its byte digest;
even reformatting the plan changes that binding.

## Explicit configuration

Repeat the intended configuration/profile at both creation and packing:

```bash
sharelint plan create ./handoff -o strict.plan.json --profile strict
sharelint pack ./handoff -o strict.zip --plan strict.plan.json --profile strict
```

The plan cannot silently increase resource budgets or weaken the command's
threshold. It cannot be combined with `pack --no-receipt`. Old plans remain
inspectable and can be used to verify historical receipts after an upgrade;
packing requires a plan produced by the current version.

## Format and exit codes

The [handoff plan schema](../schemas/handoff-plan.schema.json) has its own
`schema_version: "1.0.0"`. The canonical document checksum detects inconsistent
edits but is not authentication: anyone with the data can recompute it.

`plan create` writes a ready plan and returns `0`, or a blocked plan and returns
`1` when supported inspection finds blocking risks or coverage gaps. Invalid
input, an invalid plan, a stale/mismatched plan during packing, and I/O errors
return `2`; cancellation returns `130`. `plan inspect` returns `0` for ready and
`1` for blocked. A ready result is not a guarantee of safety or compliance.

Python users can call `create_plan(Path(...))`, `read_plan(Path(...))`, and
`pack(..., plan=Path(...))`. Write `HandoffPlan.payload` to a protected new file;
the Python creation API itself does not write to disk.
