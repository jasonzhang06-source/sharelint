"""Bounded structural PDF checks without executing or rendering the document."""

from __future__ import annotations

import re

from ..context import ScanContext

_INFO_FIELDS = {
    "Author": "SL.PDF.AUTHOR_METADATA",
    "Creator": "SL.PDF.SOFTWARE_METADATA",
    "Producer": "SL.PDF.SOFTWARE_METADATA",
}
_ACTIVE_TOKENS = (b"/JavaScript", b"/JS", b"/Launch", b"/OpenAction", b"/RichMedia")


def _literal_values(data: bytes, field: str) -> list[str]:
    pattern = re.compile(rb"/" + field.encode("ascii") + rb"\s*\((.{1,1024}?)\)", re.S)
    return [match.group(1).decode("latin-1", errors="replace") for match in pattern.finditer(data)]


def scan_pdf(data: bytes, source_chain: tuple[str, ...], context: ScanContext) -> None:
    for field, rule_id in _INFO_FIELDS.items():
        for value in _literal_values(data, field):
            context.add_finding(rule_id, source_chain, f"PDF Info /{field}", value)

    decoded = data.decode("latin-1", errors="ignore")
    for tag in ("dc:creator", "pdf:Author", "xmp:CreatorTool"):
        pattern = re.compile(rf"<{re.escape(tag)}[^>]*>(.*?)</{re.escape(tag)}>", re.I | re.S)
        for match in pattern.finditer(decoded):
            value = re.sub(r"<[^>]+>", " ", match.group(1)).strip()
            if value:
                rule_id = (
                    "SL.PDF.SOFTWARE_METADATA"
                    if tag == "xmp:CreatorTool"
                    else "SL.PDF.AUTHOR_METADATA"
                )
                context.add_finding(rule_id, source_chain, f"XMP {tag}", value)

    present_tokens = [token.decode("ascii") for token in _ACTIVE_TOKENS if token in data]
    if present_tokens:
        context.add_finding(
            "SL.PDF.ACTIVE_CONTENT",
            source_chain,
            "PDF object graph",
            ", ".join(present_tokens),
        )
    if b"/EmbeddedFile" in data or b"/EmbeddedFiles" in data:
        context.add_finding(
            "SL.PDF.EMBEDDED_FILE",
            source_chain,
            "PDF name/object tree",
            "embedded file object",
        )
    if b"/Encrypt" in data:
        context.add_finding(
            "SL.PDF.ENCRYPTED",
            source_chain,
            "PDF trailer",
            "encrypted content",
        )
    eof_count = data.count(b"%%EOF")
    if eof_count > 1:
        context.add_finding(
            "SL.PDF.INCREMENTAL_HISTORY",
            source_chain,
            "PDF revisions",
            f"{eof_count} end-of-file markers",
        )
