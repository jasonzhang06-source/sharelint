"""Builders for tiny, deterministic, wholly fictional test documents.

The fixtures deliberately use ``example.invalid`` and conspicuous ``FICTITIOUS``
markers.  Nothing in this module is copied from a real person or document.
Only the Python standard library is required so security tests can run in a
minimal CI environment.
"""

# Literal OPC XML namespace declarations and the embedded JPEG are intentionally long.
# ruff: noqa: E501

from __future__ import annotations

import base64
import binascii
import hashlib
import io
import struct
import zlib
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from xml.sax.saxutils import escape
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

FICTIONAL_NAME = "FICTITIOUS_PERSON_ALICE_EXAMPLE"
FICTIONAL_EMAIL = "alice@example.invalid"
# Structurally resembles a GitHub token so scanners exercise redaction.  The
# repeated test pattern is generated for this suite and has never been valid.
FICTIONAL_SECRET = "ghp_" + ("A" * 36)
FICTIONAL_NOTE = f"Synthetic fixture for {FICTIONAL_NAME} ({FICTIONAL_EMAIL})"

_ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)


def _as_bytes(value: str | bytes) -> bytes:
    return value.encode("utf-8") if isinstance(value, str) else value


def _zip_bytes(members: Mapping[str, str | bytes]) -> bytes:
    buffer = io.BytesIO()
    with ZipFile(buffer, "w") as archive:
        for name in sorted(members):
            info = ZipInfo(name, date_time=_ZIP_EPOCH)
            info.compress_type = ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, _as_bytes(members[name]))
    return buffer.getvalue()


def write_zip(path: Path, members: Mapping[str, str | bytes]) -> Path:
    """Write a deterministic ZIP with the supplied logical member names."""

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_zip_bytes(members))
    return path


def write_docx(
    path: Path,
    *,
    body: Sequence[str] = (FICTIONAL_NOTE,),
    author: str = FICTIONAL_NAME,
    comment: str = FICTIONAL_SECRET,
) -> Path:
    paragraphs = "".join(f"<w:p><w:r><w:t>{escape(line)}</w:t></w:r></w:p>" for line in body)
    members = {
        "[Content_Types].xml": """<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
</Types>""",
        "_rels/.rels": """<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
</Relationships>""",
        "docProps/core.xml": f"""<?xml version="1.0" encoding="UTF-8"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/">
  <dc:title>FICTITIOUS_SHARELINT_FIXTURE</dc:title>
  <dc:creator>{escape(author)}</dc:creator>
  <dc:description>{escape(comment)}</dc:description>
</cp:coreProperties>""",
        "word/document.xml": f"""<?xml version="1.0" encoding="UTF-8"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>{paragraphs}<w:sectPr/></w:body>
</w:document>""",
    }
    return write_zip(path, members)


def write_xlsx(
    path: Path,
    *,
    cells: Sequence[str] = (FICTIONAL_NOTE, FICTIONAL_SECRET),
    author: str = FICTIONAL_NAME,
) -> Path:
    rows = "".join(
        f'<row r="{index}"><c r="A{index}" t="inlineStr"><is><t>{escape(value)}</t></is></c></row>'
        for index, value in enumerate(cells, start=1)
    )
    members = {
        "[Content_Types].xml": """<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
  <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
  <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
</Types>""",
        "_rels/.rels": """<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
</Relationships>""",
        "docProps/core.xml": f"""<?xml version="1.0" encoding="UTF-8"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/">
  <dc:title>FICTITIOUS_SHARELINT_FIXTURE</dc:title><dc:creator>{escape(author)}</dc:creator>
</cp:coreProperties>""",
        "xl/workbook.xml": """<?xml version="1.0" encoding="UTF-8"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheets><sheet name="Synthetic" sheetId="1" r:id="rId1"/></sheets>
</workbook>""",
        "xl/_rels/workbook.xml.rels": """<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
</Relationships>""",
        "xl/worksheets/sheet1.xml": f"""<?xml version="1.0" encoding="UTF-8"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>{rows}</sheetData></worksheet>""",
    }
    return write_zip(path, members)


def write_pptx(
    path: Path,
    *,
    slides: Sequence[str] = (FICTIONAL_NOTE, FICTIONAL_SECRET),
    author: str = FICTIONAL_NAME,
) -> Path:
    runs = "".join(f"<a:p><a:r><a:t>{escape(text)}</a:t></a:r></a:p>" for text in slides)
    members = {
        "[Content_Types].xml": """<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/>
  <Override PartName="/ppt/slides/slide1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/>
  <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
</Types>""",
        "_rels/.rels": """<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="ppt/presentation.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
</Relationships>""",
        "docProps/core.xml": f"""<?xml version="1.0" encoding="UTF-8"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/">
  <dc:title>FICTITIOUS_SHARELINT_FIXTURE</dc:title><dc:creator>{escape(author)}</dc:creator>
</cp:coreProperties>""",
        "ppt/presentation.xml": """<?xml version="1.0" encoding="UTF-8"?>
<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <p:sldIdLst><p:sldId id="256" r:id="rId1"/></p:sldIdLst>
</p:presentation>""",
        "ppt/_rels/presentation.xml.rels": """<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide" Target="slides/slide1.xml"/>
</Relationships>""",
        "ppt/slides/slide1.xml": f"""<?xml version="1.0" encoding="UTF-8"?>
<p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">
  <p:cSld><p:spTree><p:nvGrpSpPr/><p:grpSpPr/><p:sp><p:nvSpPr/><p:spPr/><p:txBody><a:bodyPr/><a:lstStyle/>{runs}</p:txBody></p:sp></p:spTree></p:cSld>
</p:sld>""",
    }
    return write_zip(path, members)


def _pdf_literal(value: str) -> bytes:
    safe = value.encode("ascii", "replace")
    return safe.replace(b"\\", b"\\\\").replace(b"(", b"\\(").replace(b")", b"\\)")


def write_pdf(
    path: Path,
    *,
    text: str = FICTIONAL_SECRET,
    author: str = FICTIONAL_NAME,
) -> Path:
    """Write a minimal one-page PDF with visible text and an Info dictionary."""

    stream = b"BT /F1 12 Tf 72 720 Td (" + _pdf_literal(text) + b") Tj ET"
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
        b"<< /Length "
        + str(len(stream)).encode("ascii")
        + b" >>\nstream\n"
        + stream
        + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Title (FICTITIOUS_SHARELINT_FIXTURE) /Author ("
        + _pdf_literal(author)
        + b") /Subject (SYNTHETIC_ONLY) >>",
    ]
    payload = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for number, obj in enumerate(objects, start=1):
        offsets.append(len(payload))
        payload.extend(f"{number} 0 obj\n".encode("ascii"))
        payload.extend(obj)
        payload.extend(b"\nendobj\n")
    xref_offset = len(payload)
    payload.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    payload.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        payload.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    payload.extend(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R /Info 6 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n".encode(
            "ascii"
        )
    )
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return path


# A tiny baseline JPEG.  Tests inject their own EXIF APP1 block immediately
# after SOI, leaving image data untouched.
_ONE_PIXEL_JPEG = base64.b64decode(
    "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAP//////////////////////////////////////////////////////////////////////////////////////"
    "2wBDAf//////////////////////////////////////////////////////////////////////////////////////wAARCAABAAEDASIAAhEBAxEB"
    "/8QAFQABAQAAAAAAAAAAAAAAAAAAAAb/xAAUEAEAAAAAAAAAAAAAAAAAAAAA/9oADAMBAAIQAxAAAAF//8QAFBAB"
    "AAAAAAAAAAAAAAAAAAAAAP/aAAgBAQABBQJ//8QAFBEBAAAAAAAAAAAAAAAAAAAAAP/aAAgBAwEBPwF//8QAFBEBAAAA"
    "AAAAAAAAAAAAAAAAAP/aAAgBAgEBPwF//8QAFBABAAAAAAAAAAAAAAAAAAAAAP/aAAgBAQAGPwJ//8QAFBABAAAAAAAA"
    "AAAAAAAAAAAAAP/aAAgBAQABPyF//9oADAMBAAIAAwAAABD/xAAUEQEAAAAAAAAAAAAAAAAAAAAA/9oACAEDAQE/EH//"
    "xAAUEQEAAAAAAAAAAAAAAAAAAAAA/9oACAECAQE/EH//xAAUEAEAAAAAAAAAAAAAAAAAAAAA/9oACAEBAAE/EH//2Q=="
)


def _exif_ascii(entries: Sequence[tuple[int, str]]) -> bytes:
    encoded = [(tag, value.encode("ascii", "replace") + b"\0") for tag, value in entries]
    data_offset = 8 + 2 + 12 * len(encoded) + 4
    table = bytearray(struct.pack("<H", len(encoded)))
    data = bytearray()
    for tag, value in encoded:
        table.extend(struct.pack("<HHI", tag, 2, len(value)))
        if len(value) <= 4:
            table.extend(value.ljust(4, b"\0"))
        else:
            table.extend(struct.pack("<I", data_offset + len(data)))
            data.extend(value)
    table.extend(struct.pack("<I", 0))
    return b"II*\x00\x08\x00\x00\x00" + bytes(table) + bytes(data)


def write_jpeg(
    path: Path,
    *,
    description: str = FICTIONAL_SECRET,
    artist: str = FICTIONAL_NAME,
) -> Path:
    exif = b"Exif\0\0" + _exif_ascii(((0x010E, description), (0x013B, artist)))
    if len(exif) + 2 > 0xFFFF:
        raise ValueError("EXIF fixture is too large")
    app1 = b"\xff\xe1" + struct.pack(">H", len(exif) + 2) + exif
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_ONE_PIXEL_JPEG[:2] + app1 + _ONE_PIXEL_JPEG[2:])
    return path


def _png_chunk(kind: bytes, data: bytes) -> bytes:
    return (
        struct.pack(">I", len(data))
        + kind
        + data
        + struct.pack(">I", binascii.crc32(kind + data) & 0xFFFFFFFF)
    )


def write_png(
    path: Path,
    *,
    description: str = FICTIONAL_SECRET,
    author: str = FICTIONAL_NAME,
) -> Path:
    raw_pixel = b"\x00\xff\xff\xff"  # filter byte followed by one white RGB pixel
    payload = bytearray(b"\x89PNG\r\n\x1a\n")
    payload.extend(_png_chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)))
    payload.extend(_png_chunk(b"tEXt", b"Author\0" + author.encode("latin-1", "replace")))
    payload.extend(_png_chunk(b"tEXt", b"Description\0" + description.encode("latin-1", "replace")))
    payload.extend(_png_chunk(b"IDAT", zlib.compress(raw_pixel, level=9)))
    payload.extend(_png_chunk(b"IEND", b""))
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return path


def write_nested_zip(path: Path, *, member_name: str, payload: bytes) -> Path:
    """Wrap a payload in two ZIP layers for provenance tests."""

    inner = _zip_bytes({member_name: payload})
    return write_zip(path, {"level-one/inner.zip": inner})


def write_traversal_zip(path: Path) -> Path:
    return write_zip(
        path,
        {
            "../FICTITIOUS_ESCAPE.txt": "synthetic traversal payload",
            "safe/../../FICTITIOUS_NESTED_ESCAPE.txt": "synthetic traversal payload",
            "..\\FICTITIOUS_WINDOWS_ESCAPE.txt": "synthetic traversal payload",
            "safe/ordinary.txt": "ordinary synthetic content",
        },
    )


def write_zip_bomb(path: Path, *, uncompressed_size: int = 8 * 1024 * 1024) -> Path:
    """Create a small high-ratio archive, not a destructive recursive bomb."""

    if uncompressed_size < 1024:
        raise ValueError("uncompressed_size must be at least 1024 bytes")
    return write_zip(path, {"FICTITIOUS_HIGH_RATIO.bin": b"0" * uncompressed_size})


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(128 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def iter_png_chunks(payload: bytes) -> Iterable[tuple[bytes, bytes]]:
    """A tiny strict-enough parser used to validate generated PNG fixtures."""

    if not payload.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError("not a PNG")
    offset = 8
    while offset < len(payload):
        length = struct.unpack(">I", payload[offset : offset + 4])[0]
        kind = payload[offset + 4 : offset + 8]
        data = payload[offset + 8 : offset + 8 + length]
        expected = struct.unpack(">I", payload[offset + 8 + length : offset + 12 + length])[0]
        if (binascii.crc32(kind + data) & 0xFFFFFFFF) != expected:
            raise ValueError(f"bad CRC for {kind!r}")
        yield kind, data
        offset += 12 + length
