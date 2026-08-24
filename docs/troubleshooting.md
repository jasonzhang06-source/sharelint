# Installation and troubleshooting

ShareLint requires Python 3.11 or newer. The package is published on
[PyPI](https://pypi.org/project/sharelint/) and exposes the `sharelint` command.
Installation downloads the package; scanning itself has no upload, telemetry,
account, or network feature.

## Recommended isolated installation

Use [pipx](https://pipx.pypa.io/stable/) to keep the CLI separate from project
and system Python environments:

```bash
pipx install sharelint
sharelint --version
sharelint demo
```

Upgrade or remove it later with:

```bash
pipx upgrade sharelint
pipx uninstall sharelint
```

If you already use [uv](https://docs.astral.sh/uv/guides/tools/):

```bash
uv tool install sharelint
sharelint --version
sharelint demo
```

The corresponding maintenance commands are:

```bash
uv tool upgrade sharelint
uv tool uninstall sharelint
```

## Standard virtual environment

On Linux or macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install sharelint
sharelint --version
sharelint demo
```

On Windows PowerShell:

```powershell
py -3.11 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install sharelint
sharelint --version
sharelint demo
```

The same package targets Linux, Windows, and macOS, but validation is tied to a
specific CI commit and writable outputs require filesystem hard-link support.
Read [Platform support](platform-support.md) before using FAT/exFAT, network,
synchronized, or virtual filesystems.

Do not use `sudo pip install` and do not bypass an
`externally-managed-environment` error with `--break-system-packages`. That
message means the operating system protects its Python installation. Use pipx,
uv, or a virtual environment instead.

## `sharelint: command not found`

First confirm that the selected installer can see the application:

```bash
pipx list
uv tool list
```

For pipx, run `pipx ensurepath`, then open a new terminal. For an ordinary
virtual environment, activate it before running `sharelint`. You can also verify
the package through the active interpreter:

```bash
python -m pip show sharelint
python -m sharelint --version
```

## Python version errors

Check the interpreter selected by your shell:

```bash
python --version
python3 --version
```

ShareLint does not support Python 3.10 or older. Installing a newer Python does
not always change the existing `python` command; explicitly select the newer
interpreter when creating the virtual environment.

## Exit status and incomplete coverage

The CLI uses these stable exit codes:

| Code | Meaning |
| ---: | --- |
| `0` | The command completed and the selected gate did not block. |
| `1` | A finding met the threshold, strict coverage failed, or `pack` was blocked. |
| `2` | Usage was invalid, the target was unreadable, or another operational error occurred. |

`sharelint demo` intentionally returns `0` after showing a synthetic blocked
example. A normal `scan` can also return `0` while reporting `INCOMPLETE` unless
`--strict` was selected. Use this in automation when every required surface
must be inspected:

```bash
sharelint scan ./handoff --strict --fail-on high
```

PDF rendered pages and image pixels are not OCR-scanned in the dependency-free
baseline. Their coverage gap is expected and visible. `pack` is stricter and
will not publish an archive while any required surface is partial, skipped, or
errored.

## Report output errors

ShareLint refuses to overwrite existing reports, demo bundles, archives, and
receipts. Choose a new output path or deliberately move the old file first.
Reports for a directory scan must also be written outside that directory.

To create a local HTML report from synthetic data without printing HTML into
the terminal:

```bash
sharelint demo --format html --report sharelint-demo.html
```

The report is self-contained. It can contain sensitive context such as masked
finding types and filenames, so protect it even though complete matched values
are not included.

## Ask for help safely

Collect only the following before opening a
[setup question](https://github.com/jasonzhang06-source/sharelint/issues/new?template=question.yml):

```bash
sharelint --version
python --version
```

Describe the operating system, installation method, sanitized command, and
exact generic error class. Never attach a real input document, raw finding,
secret, personal identifier, private local path, or confidential report. Report
possible vulnerabilities privately according to the
[security policy](../SECURITY.md).
