"""A reproducible synthetic bundle used by the README and `sharelint demo`."""

from __future__ import annotations

import io
import os
import tempfile
import zipfile
from contextlib import suppress
from pathlib import Path


def render_demo_console(report_text: str, *, saved_bundle: str | None = None) -> str:
    """Frame a console report so a first-time user understands the demo boundary."""

    lines = [
        "SYNTHETIC DEMO · generated sample only",
        "No personal files were read; this run scanned only files created by ShareLint.",
    ]
    if saved_bundle is not None:
        lines.append(f"Synthetic demo bundle saved · {saved_bundle}")
    lines.extend(
        [
            "",
            report_text.rstrip("\n"),
            "",
            "Next steps",
            "  Scan a file or folder: sharelint scan ./path-to-share",
            "  After review, pack approved files: "
            "sharelint pack ./approved-files -o share-ready.zip",
        ]
    )
    return "\n".join(lines) + "\n"


def _zip_bytes(files: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(files):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            info.flag_bits |= 0x800
            archive.writestr(info, files[name], compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    return output.getvalue()


def _xlsx() -> bytes:
    return _zip_bytes(
        {
            "[Content_Types].xml": b"<Types/>",
            "xl/workbook.xml": (
                b'<workbook xmlns="urn:demo"><sheets>'
                b'<sheet name="Clients" state="veryHidden" sheetId="1"/>'
                b"</sheets></workbook>"
            ),
            "xl/sharedStrings.xml": (
                b'<sst xmlns="urn:demo"><si><t>AKIAIOSFODNN7EXAMPLE</t></si></sst>'
            ),
        }
    )


def _pptx() -> bytes:
    return _zip_bytes(
        {
            "[Content_Types].xml": b"<Types/>",
            "docProps/core.xml": (
                b'<cp:coreProperties xmlns:cp="urn:cp" xmlns:dc="urn:dc">'
                b"<dc:creator>Casey Example</dc:creator></cp:coreProperties>"
            ),
            "ppt/presentation.xml": b'<p:presentation xmlns:p="urn:demo"/>',
            "ppt/slides/slide1.xml": b'<p:sld xmlns:p="urn:demo"><a:t xmlns:a="urn:a">Public demo</a:t></p:sld>',
            "ppt/notesSlides/notesSlide1.xml": (
                b'<p:notes xmlns:p="urn:demo" xmlns:a="urn:a">'
                b"<a:t>Follow up with reviewer@example.test</a:t></p:notes>"
            ),
            "ppt/embeddings/clients.xlsx": _xlsx(),
        }
    )


def create_demo_bundle(path: Path) -> Path:
    """Atomically create a bundle containing only documented synthetic evidence."""

    report = (
        b"%PDF-1.4\n"
        b"1 0 obj << /Author (Casey Example) /Producer (Synthetic Demo) "
        b"/OpenAction 2 0 R >> endobj\n"
        b"2 0 obj << /S /JavaScript /JS (app.alert('demo')) >> endobj\n"
        b"%%EOF\n"
    )
    payload = _zip_bytes(
        {
            "README.txt": b"Synthetic ShareLint demo. No real identities or credentials.\n",
            "deck.pptx": _pptx(),
            "report.pdf": report,
        }
    )
    if path.exists() or path.is_symlink():
        raise FileExistsError("refusing to overwrite an existing demo bundle")
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=path.parent,
            delete=False,
            mode="wb",
        ) as handle:
            temporary = Path(handle.name)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, path)
    finally:
        if temporary is not None:
            with suppress(OSError):
                temporary.unlink(missing_ok=True)
    return path
