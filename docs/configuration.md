# Policies and configuration

ShareLint 1.1 adds explicit, data-only TOML configuration. It never discovers
configuration automatically in a scanned directory or a parent directory.
An untrusted handoff cannot silently select a weaker policy.

## Built-in policies

| Profile | Finding threshold | Incomplete `scan` exits 1 |
| --- | --- | --- |
| `default` | high | No (same default as 1.0) |
| `public` | medium | Yes |
| `strict` | low | Yes |

All findings and coverage gaps remain in reports regardless of the threshold.
`public` is a convenience preset, not a guarantee of safe public disclosure.
`pack` always requires complete coverage with every profile, even if `strict`
is false in the configuration.

```sh
sharelint scan ./handoff --profile public
sharelint config show --profile strict
sharelint config init -o sharelint.toml
sharelint scan ./handoff --config sharelint.toml --profile client
sharelint pack ./approved-files -o approved.zip --config sharelint.toml --profile client
```

`config init` creates a new file without overwriting existing content. It does
not activate that file. `config show` prints the full effective threshold,
coverage behavior, and resource limits as JSON, without echoing the file path.

## TOML shape

```toml
schema_version = 1
default_profile = "client"

[scan]
fail_on = "high"
strict = false

[limits]
max_file_bytes = 67108864
max_total_bytes = 268435456

[profiles.client]
fail_on = "medium"
strict = true

[profiles.client.limits]
max_archive_depth = 3
```

All nine `ScanLimits` fields shown by `config show` can be configured. Omitted
limits retain their existing defaults. Limits must have the documented positive
integer/finite numeric types. Exceeding a limit remains an explicit coverage
gap, not a clean result. Larger limits increase memory and processing exposure.
Use trusted, reviewed settings for untrusted input.

Resolution order:

1. Start with 1.0-compatible defaults.
2. Apply the explicit configuration's `[scan]` and `[limits]` tables.
3. Apply the selected named profile, including its nested limits. The built-in
   `public` and `strict` profiles override the base threshold and strictness;
   their names cannot be redefined in TOML.
4. Apply explicit command-line `--fail-on`, `--strict`, or `--no-strict` overrides.

`--profile` overrides `default_profile`. Without either, use `default`.
`--no-strict` exists only for `scan` and `config show`; it never relaxes `pack`.
The effective threshold and limits are recorded in existing reports and
hash-bound pack policies; report/receipt schema versions remain `1.0.0`.

Configuration is limited to 64 KiB and 64 custom profiles. Names are lowercase
ASCII identifiers, up to 64 characters. Unknown keys, malformed tables,
duplicate TOML keys, unsupported versions, invalid unused profiles, symlinks,
special files, and detected read-time changes are rejected with exit code 2.
There is no environment-variable expansion, network include, executable code,
rule suppression, or automatic path exclusion in configuration schema 1.
