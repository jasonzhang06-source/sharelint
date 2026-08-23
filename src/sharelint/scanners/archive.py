"""Bounded, in-memory ZIP and OOXML traversal."""

from __future__ import annotations

import io
import lzma
import re
import stat
import zipfile
import zlib
from pathlib import PurePosixPath

from ..context import ScanContext
from ..models import SurfaceStatus
from .ooxml import inspect_ooxml
from .path import scan_name
from .text import scan_text

_DRIVE_RE = re.compile(r"^[A-Za-z]:")
_KNOWN_EXTRA_FIELD_IDS = {
    0x0001,  # ZIP64
    0x000A,  # NTFS timestamps
    0x000D,  # PKWARE Unix
    0x5455,  # extended timestamp
    0x5855,  # old Info-ZIP Unix
    0x6375,  # Unicode comment
    0x7075,  # Unicode path
    0x7855,  # Info-ZIP Unix
    0x7875,  # Info-ZIP Unix UID/GID
}


def has_excessive_central_directory(data: bytes, limit: int) -> bool:
    """Reject huge ZIP entry tables before ZipFile allocates a ZipInfo per entry."""

    return data.count(b"PK\x01\x02") > limit


def normalized_member_name(name: str) -> str | None:
    normalized = name.replace("\\", "/")
    if (
        not normalized
        or "\x00" in normalized
        or normalized.startswith("/")
        or any(0xD800 <= ord(character) <= 0xDFFF for character in normalized)
    ):
        return None
    if _DRIVE_RE.match(normalized):
        return None
    parts = PurePosixPath(normalized).parts
    if any(part in {"", ".", ".."} for part in parts):
        return None
    return "/".join(parts)


def _is_symlink(info: zipfile.ZipInfo) -> bool:
    mode = (info.external_attr >> 16) & 0xFFFF
    return stat.S_IFMT(mode) == stat.S_IFLNK


def _scan_metadata_bytes(
    payload: bytes,
    source_chain: tuple[str, ...],
    context: ScanContext,
    *,
    kind: str,
    location: str,
    partial_note: str = "",
) -> None:
    if not payload:
        return
    inspected = payload[: context.limits.max_text_chars]
    scan_text(
        inspected.decode("latin-1"),
        source_chain,
        context,
        location_prefix=location,
    )
    truncated = len(inspected) < len(payload)
    note = partial_note or ("metadata text character limit reached" if truncated else "")
    context.add_surface(
        source_chain,
        kind,
        SurfaceStatus.PARTIAL if note else SurfaceStatus.SCANNED,
        len(inspected),
        "archive-metadata",
        note,
    )


def _extra_fields_note(extra: bytes) -> str:
    offset = 0
    unknown: set[int] = set()
    while offset < len(extra):
        if offset + 4 > len(extra):
            return "ZIP extra-field framing was truncated"
        field_id = int.from_bytes(extra[offset : offset + 2], "little")
        size = int.from_bytes(extra[offset + 2 : offset + 4], "little")
        offset += 4
        if offset + size > len(extra):
            return "ZIP extra-field payload was truncated"
        if field_id not in _KNOWN_EXTRA_FIELD_IDS:
            unknown.add(field_id)
        offset += size
    if unknown:
        identifiers = ", ".join(f"0x{value:04x}" for value in sorted(unknown)[:8])
        return f"unknown ZIP extra-field type(s) {identifiers} were not structurally interpreted"
    return ""


def scan_archive(
    data: bytes,
    source_chain: tuple[str, ...],
    context: ScanContext,
    *,
    depth: int,
) -> str | None:
    """Scan an archive and recursively dispatch safe, bounded member buffers."""

    if depth >= context.limits.max_archive_depth:
        context.add_finding(
            "SL.ARCHIVE.LIMIT_EXCEEDED",
            source_chain,
            "archive nesting depth",
            f"depth {depth + 1} exceeds configured limit",
        )
        context.add_surface(
            source_chain,
            "archive-coverage",
            SurfaceStatus.PARTIAL,
            0,
            "archive",
            "archive nesting depth limit reached",
        )
        return None

    if has_excessive_central_directory(data, context.limits.max_archive_members):
        context.add_finding(
            "SL.ARCHIVE.LIMIT_EXCEEDED",
            source_chain,
            "ZIP central-directory record count",
            "configured member count exceeded before ZIP parsing",
        )
        context.add_surface(
            source_chain,
            "archive-coverage",
            SurfaceStatus.PARTIAL,
            0,
            "archive",
            "ZIP member-count limit reached before allocation",
        )
        return None

    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
        infos = archive.infolist()
    except (zipfile.BadZipFile, OSError, ValueError):
        context.add_error(source_chain, "SL.SCAN.READ_ERROR", "ZIP structure could not be parsed")
        return None

    _scan_metadata_bytes(
        archive.comment,
        source_chain + ("<zip-comment>",),
        context,
        kind="zip-comment",
        location="ZIP archive comment",
    )

    readable: list[tuple[str, bytes]] = []
    names_seen: set[str] = set()
    limit_reported = False
    with archive:
        for info in infos:
            if not context.consume_member():
                if not limit_reported:
                    context.add_finding(
                        "SL.ARCHIVE.LIMIT_EXCEEDED",
                        source_chain,
                        "archive member count",
                        "configured member count exceeded",
                    )
                    context.add_surface(
                        source_chain,
                        "archive-coverage",
                        SurfaceStatus.PARTIAL,
                        0,
                        "archive",
                        "archive member-count limit reached",
                    )
                    limit_reported = True
                break

            normalized = normalized_member_name(info.filename)
            display_name = (
                context.display_path(normalized)
                if normalized is not None
                else f"<unsafe-member-path> [path-ref:{context.path_reference(info.filename)}]"
            )
            member_chain = source_chain + (display_name,)
            _scan_metadata_bytes(
                info.comment,
                member_chain + ("<zip-entry-comment>",),
                context,
                kind="zip-entry-comment",
                location="ZIP entry comment",
            )
            _scan_metadata_bytes(
                info.extra,
                member_chain + ("<zip-extra-fields>",),
                context,
                kind="zip-extra-fields",
                location="ZIP entry extra fields",
                partial_note=_extra_fields_note(info.extra),
            )
            if normalized is None:
                context.add_finding(
                    "SL.ARCHIVE.PATH_TRAVERSAL",
                    member_chain,
                    "archive member name",
                    info.filename,
                    evidence_kind="path",
                )
                context.add_surface(
                    member_chain,
                    "archive-member",
                    SurfaceStatus.SKIPPED,
                    0,
                    "archive",
                    "unsafe member path",
                )
                continue
            scan_name(normalized, member_chain, context)
            if normalized in names_seen:
                context.add_finding(
                    "SL.ARCHIVE.DUPLICATE_PATH",
                    member_chain,
                    "normalized member path",
                    normalized,
                    evidence_kind="path",
                )
                context.add_surface(
                    member_chain,
                    "archive-member",
                    SurfaceStatus.SKIPPED,
                    0,
                    "archive",
                    "duplicate normalized path",
                )
                continue
            names_seen.add(normalized)
            if info.is_dir():
                continue
            if _is_symlink(info):
                context.add_finding(
                    "SL.ARCHIVE.SYMLINK",
                    member_chain,
                    "archive member type",
                    normalized,
                    evidence_kind="path",
                )
                context.add_surface(
                    member_chain,
                    "archive-symlink",
                    SurfaceStatus.SKIPPED,
                    0,
                    "archive",
                    "symbolic links are not followed",
                )
                continue
            if info.flag_bits & 0x1:
                context.add_finding(
                    "SL.ARCHIVE.ENCRYPTED_MEMBER",
                    member_chain,
                    "archive encryption flag",
                    normalized,
                    evidence_kind="path",
                )
                context.add_surface(
                    member_chain,
                    "encrypted-member",
                    SurfaceStatus.SKIPPED,
                    0,
                    "archive",
                    "encrypted member cannot be inspected",
                )
                continue

            ratio = (
                float("inf")
                if info.compress_size == 0 and info.file_size > 0
                else info.file_size / max(1, info.compress_size)
            )
            if (
                info.file_size > context.limits.max_member_bytes
                or ratio > context.limits.max_compression_ratio
            ):
                context.add_finding(
                    "SL.ARCHIVE.LIMIT_EXCEEDED",
                    member_chain,
                    "archive member size or compression ratio",
                    f"member size {info.file_size}; ratio {ratio:.1f}",
                )
                context.add_surface(
                    member_chain,
                    "archive-member",
                    SurfaceStatus.SKIPPED,
                    0,
                    "archive",
                    "member exceeded a safety limit",
                )
                continue
            runtime_limit = min(context.limits.max_member_bytes, context.remaining_bytes)
            ratio_limit = int(context.limits.max_compression_ratio * max(1, info.compress_size))
            runtime_limit = min(runtime_limit, ratio_limit)
            if runtime_limit <= 0:
                context.add_finding(
                    "SL.ARCHIVE.LIMIT_EXCEEDED",
                    member_chain,
                    "total decompressed-byte budget",
                    "configured total byte budget exceeded",
                )
                context.add_surface(
                    member_chain,
                    "archive-member",
                    SurfaceStatus.SKIPPED,
                    0,
                    "archive",
                    "scan byte budget exhausted",
                )
                continue
            try:
                with archive.open(info, "r") as member:
                    member_data = member.read(runtime_limit + 1)
            except (
                EOFError,
                RuntimeError,
                ValueError,
                zipfile.BadZipFile,
                lzma.LZMAError,
                OSError,
                NotImplementedError,
                zlib.error,
            ):
                context.add_error(
                    member_chain,
                    "SL.SCAN.READ_ERROR",
                    "Archive member could not be read",
                )
                context.add_surface(
                    member_chain,
                    "archive-member",
                    SurfaceStatus.SKIPPED,
                    0,
                    "archive",
                    "member read failed",
                )
                continue
            if len(member_data) > runtime_limit:
                context.consume(runtime_limit)
                context.add_finding(
                    "SL.ARCHIVE.LIMIT_EXCEEDED",
                    member_chain,
                    "runtime expanded-byte budget",
                    "member expanded beyond the configured runtime limit",
                )
                context.add_surface(
                    member_chain,
                    "archive-member",
                    SurfaceStatus.SKIPPED,
                    runtime_limit,
                    "archive",
                    "member exceeded a runtime safety limit",
                )
                continue
            if len(member_data) != info.file_size:
                context.consume(len(member_data))
                context.add_error(
                    member_chain,
                    "SL.SCAN.READ_ERROR",
                    "Archive member size did not match its directory record",
                )
                context.add_surface(
                    member_chain,
                    "archive-member",
                    SurfaceStatus.SKIPPED,
                    len(member_data),
                    "archive",
                    "member size validation failed",
                )
                continue
            if not context.consume(len(member_data)):
                context.add_error(
                    member_chain,
                    "SL.SCAN.READ_ERROR",
                    "Archive byte accounting failed",
                )
                continue
            readable.append((normalized, member_data))

    members = dict(readable)
    office_kind = inspect_ooxml(members, source_chain, context)

    # Import here so the dispatcher can recurse without a module import cycle.
    from ..scanner import scan_blob

    for normalized, member_data in readable:
        scan_blob(
            normalized,
            member_data,
            source_chain + (context.display_path(normalized),),
            context,
            depth=depth + 1,
            already_counted=True,
        )
    return office_kind
