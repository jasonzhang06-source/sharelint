"""Metadata readers for common image containers using only the standard library."""

from __future__ import annotations

import struct
import zlib
from collections.abc import Iterator

from ..context import ScanContext
from .text import scan_text

IDENTITY_TAGS = {0x010E, 0x013B, 0x8298, 0xA430}
DEVICE_TAGS = {0x010F, 0x0110, 0x0131, 0xA431, 0xA433, 0xA434, 0xA435}
EXIF_POINTER = 0x8769
GPS_POINTER = 0x8825


def _bounded_decompress(data: bytes, limit: int = 1_048_576) -> bytes:
    try:
        decompressor = zlib.decompressobj()
        output = decompressor.decompress(data, limit + 1)
    except zlib.error:
        return b""
    if len(output) > limit or decompressor.unconsumed_tail:
        return b""
    return output


def _jpeg_segments(data: bytes) -> Iterator[tuple[int, bytes]]:
    if not data.startswith(b"\xff\xd8"):
        return
    offset = 2
    while offset + 4 <= len(data):
        if data[offset] != 0xFF:
            break
        marker = data[offset + 1]
        offset += 2
        if marker in {0xD8, 0xD9}:
            continue
        if marker == 0xDA:
            break
        length = int.from_bytes(data[offset : offset + 2], "big")
        if length < 2 or offset + length > len(data):
            break
        yield marker, data[offset + 2 : offset + length]
        offset += length


def _ifd_entries(tiff: bytes, offset: int, endian: str) -> Iterator[tuple[int, int, int, int]]:
    if offset < 0 or offset + 2 > len(tiff):
        return
    count = struct.unpack_from(f"{endian}H", tiff, offset)[0]
    if count > 4096 or offset + 2 + count * 12 > len(tiff):
        return
    for index in range(count):
        entry_offset = offset + 2 + index * 12
        tag, value_type, value_count, value_or_offset = struct.unpack_from(
            f"{endian}HHII", tiff, entry_offset
        )
        yield tag, value_type, value_count, value_or_offset


def _ascii_value(tiff: bytes, endian: str, value_type: int, count: int, value: int) -> str:
    if value_type != 2 or count <= 0 or count > 65536:
        return ""
    if count <= 4:
        packed = struct.pack(f"{endian}I", value)[:count]
    elif value + count <= len(tiff):
        packed = tiff[value : value + count]
    else:
        return ""
    return packed.rstrip(b"\x00").decode("utf-8", errors="replace").strip()


def _scan_tiff(tiff: bytes, source_chain: tuple[str, ...], context: ScanContext) -> None:
    if len(tiff) < 8:
        return
    endian = "<" if tiff[:2] == b"II" else ">" if tiff[:2] == b"MM" else ""
    if not endian or struct.unpack_from(f"{endian}H", tiff, 2)[0] != 42:
        return
    root_offset = struct.unpack_from(f"{endian}I", tiff, 4)[0]
    pending = [root_offset]
    visited: set[int] = set()
    while pending and len(visited) < 8:
        offset = pending.pop()
        if offset in visited:
            continue
        visited.add(offset)
        for tag, value_type, count, value in _ifd_entries(tiff, offset, endian):
            if tag == GPS_POINTER:
                gps_entries = list(_ifd_entries(tiff, value, endian))
                if gps_entries:
                    context.add_finding(
                        "SL.IMAGE.GPS_METADATA",
                        source_chain,
                        "EXIF GPS IFD",
                        f"GPS metadata with {len(gps_entries)} fields",
                    )
            elif tag == EXIF_POINTER:
                pending.append(value)
            elif tag in IDENTITY_TAGS | DEVICE_TAGS:
                text = _ascii_value(tiff, endian, value_type, count, value)
                if text:
                    rule_id = (
                        "SL.IMAGE.IDENTITY_METADATA"
                        if tag in IDENTITY_TAGS
                        else "SL.IMAGE.DEVICE_METADATA"
                    )
                    context.add_finding(rule_id, source_chain, f"EXIF tag 0x{tag:04X}", text)


def _scan_xmp(payload: bytes, source_chain: tuple[str, ...], context: ScanContext) -> None:
    text = payload[: context.limits.max_text_chars].decode("utf-8", errors="ignore")
    lowered = text.lower()
    if any(token in lowered for token in ("gpslatitude", "gpslongitude", "location")):
        context.add_finding(
            "SL.IMAGE.GPS_METADATA",
            source_chain,
            "XMP location field",
            "XMP location metadata",
        )
    if any(token in lowered for token in ("dc:creator", "photoshop:authorsposition", "ownername")):
        context.add_finding(
            "SL.IMAGE.IDENTITY_METADATA",
            source_chain,
            "XMP identity field",
            "XMP identity metadata",
        )
    scan_text(text, source_chain, context, location_prefix="XMP")


def _scan_png(data: bytes, source_chain: tuple[str, ...], context: ScanContext) -> None:
    offset = 8
    while offset + 12 <= len(data):
        size = int.from_bytes(data[offset : offset + 4], "big")
        chunk_type = data[offset + 4 : offset + 8]
        end = offset + 12 + size
        if size > 16 * 1024 * 1024 or end > len(data):
            break
        payload = data[offset + 8 : offset + 8 + size]
        if chunk_type == b"eXIf":
            _scan_tiff(payload, source_chain, context)
        elif chunk_type == b"tEXt":
            keyword, _, value = payload.partition(b"\x00")
            text = value[: context.limits.max_text_chars].decode("latin-1", errors="replace")
            context.add_finding(
                "SL.IMAGE.TEXT_METADATA",
                source_chain,
                "PNG tEXt chunk",
                text or keyword.decode("latin-1", errors="replace"),
            )
            scan_text(text, source_chain, context, location_prefix="PNG tEXt")
        elif chunk_type == b"zTXt":
            _keyword, _, compressed = payload.partition(b"\x00")
            if compressed[:1] == b"\x00":
                text_bytes = _bounded_decompress(compressed[1:])
                if text_bytes:
                    text = text_bytes.decode("latin-1", errors="replace")
                    context.add_finding(
                        "SL.IMAGE.TEXT_METADATA",
                        source_chain,
                        "PNG zTXt chunk",
                        text,
                    )
                    scan_text(text, source_chain, context, location_prefix="PNG zTXt")
        elif chunk_type == b"iTXt":
            _scan_xmp(payload, source_chain, context)
        if chunk_type == b"IEND":
            break
        offset = end


def _scan_webp(data: bytes, source_chain: tuple[str, ...], context: ScanContext) -> None:
    offset = 12
    while offset + 8 <= len(data):
        kind = data[offset : offset + 4]
        size = int.from_bytes(data[offset + 4 : offset + 8], "little")
        start = offset + 8
        end = start + size
        if size > 16 * 1024 * 1024 or end > len(data):
            break
        payload = data[start:end]
        if kind == b"EXIF":
            _scan_tiff(payload, source_chain, context)
        elif kind == b"XMP ":
            _scan_xmp(payload, source_chain, context)
        offset = end + (size % 2)


def scan_image(
    kind: str,
    data: bytes,
    source_chain: tuple[str, ...],
    context: ScanContext,
) -> None:
    if kind == "jpeg":
        for marker, payload in _jpeg_segments(data):
            if marker == 0xE1 and payload.startswith(b"Exif\x00\x00"):
                _scan_tiff(payload[6:], source_chain, context)
            elif marker == 0xE1 and b"xap/1.0" in payload[:64]:
                _scan_xmp(payload, source_chain, context)
            elif marker == 0xFE:
                text = payload.decode("latin-1", errors="replace")
                context.add_finding("SL.IMAGE.TEXT_METADATA", source_chain, "JPEG comment", text)
                scan_text(text, source_chain, context, location_prefix="JPEG comment")
    elif kind in {"tiff"}:
        _scan_tiff(data, source_chain, context)
    elif kind == "png":
        _scan_png(data, source_chain, context)
    elif kind == "webp":
        _scan_webp(data, source_chain, context)
    elif kind == "gif":
        # GIF comments are plain text but a full frame decoder is intentionally out of scope.
        scan_text(
            data[: context.limits.max_text_chars].decode("latin-1", errors="ignore"),
            source_chain,
            context,
            location_prefix="GIF",
        )
