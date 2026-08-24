"""Top-level filesystem and in-memory scanning orchestration."""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

from .context import ScanContext
from .extended_attributes import (
    EXTENDED_ATTRIBUTE_ERROR_MESSAGE,
    ExtendedAttributeStatus,
    probe_extended_attributes,
)
from .filesystem import (
    bounded_directory_tree,
    metadata_is_filesystem_link,
    metadata_matches_open_file,
)
from .models import ScanLimits, ScanReport, SurfaceStatus
from .scanners.detect import decode_text, detect_kind
from .scanners.image import scan_image
from .scanners.path import scan_name
from .scanners.pdf import scan_pdf
from .scanners.text import scan_text
from .windows_streams import record_windows_stream_coverage


class ScanInputError(ValueError):
    """Raised for a missing or unsupported top-level target."""


def _surface(
    context: ScanContext,
    source_chain: tuple[str, ...],
    kind: str,
    status: SurfaceStatus,
    size: int,
    scanner: str,
    note: str = "",
) -> None:
    context.add_surface(source_chain, kind, status, size, scanner, note)


def _record_extended_attribute_coverage(
    path: Path,
    source_chain: tuple[str, ...],
    context: ScanContext,
) -> None:
    status = probe_extended_attributes(path)
    if status is ExtendedAttributeStatus.NOT_APPLICABLE:
        return
    if status is ExtendedAttributeStatus.ABSENT:
        _surface(
            context,
            source_chain,
            "filesystem-extended-attributes",
            SurfaceStatus.SCANNED,
            0,
            "filesystem-xattrs",
        )
        return
    if status is ExtendedAttributeStatus.PRESENT:
        context.add_finding(
            "SL.FILESYSTEM.EXTENDED_ATTRIBUTES",
            source_chain,
            "extended filesystem metadata",
            "extended attributes present",
        )
        _surface(
            context,
            source_chain,
            "filesystem-extended-attributes",
            SurfaceStatus.SKIPPED,
            0,
            "filesystem-xattrs",
            "extended attribute values and resource forks were not inspected",
        )
        return
    context.add_error(source_chain, "SL.SCAN.READ_ERROR", EXTENDED_ATTRIBUTE_ERROR_MESSAGE)
    _surface(
        context,
        source_chain,
        "filesystem-extended-attributes",
        SurfaceStatus.SKIPPED,
        0,
        "filesystem-xattrs",
        "extended attribute enumeration failed",
    )


def _record_platform_filesystem_coverage(
    path: Path,
    source_chain: tuple[str, ...],
    context: ScanContext,
    *,
    is_directory: bool,
) -> None:
    _record_extended_attribute_coverage(path, source_chain, context)
    record_windows_stream_coverage(
        path,
        source_chain,
        context,
        is_directory=is_directory,
    )


def _file_state(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _filesystem_name_bytes(name: str) -> bytes:
    """Encode a manifest path with the host filesystem's lossless error handler."""

    return os.fsencode(name)


def _record_directory_platform_coverage(
    path: Path,
    source_chain: tuple[str, ...],
    context: ScanContext,
    metadata: os.stat_result,
) -> bool:
    _record_platform_filesystem_coverage(
        path,
        source_chain,
        context,
        is_directory=True,
    )
    try:
        current = path.stat(follow_symlinks=False)
    except OSError:
        current = None
    if (
        current is None
        or metadata_is_filesystem_link(current)
        or not stat.S_ISDIR(current.st_mode)
        or _file_state(current) != _file_state(metadata)
    ):
        context.add_error(
            source_chain,
            "SL.SCAN.READ_ERROR",
            "Directory identity changed during metadata inspection",
        )
        _surface(
            context,
            source_chain,
            "directory",
            SurfaceStatus.SKIPPED,
            0,
            "filesystem",
            "directory identity changed during metadata inspection",
        )
        return False
    return True


def scan_blob(
    name: str,
    data: bytes,
    source_chain: tuple[str, ...],
    context: ScanContext,
    *,
    depth: int = 0,
    already_counted: bool = False,
) -> None:
    """Dispatch one bounded byte buffer to a content-aware scanner."""

    if not already_counted and not context.consume(len(data)):
        context.add_finding(
            "SL.ARCHIVE.LIMIT_EXCEEDED",
            source_chain,
            "total scan-byte budget",
            "configured total byte budget exceeded",
        )
        _surface(
            context,
            source_chain,
            "unknown",
            SurfaceStatus.SKIPPED,
            0,
            "dispatcher",
            "scan byte budget exhausted",
        )
        return

    kind = detect_kind(name, data)
    if kind == "zip":
        from .scanners.archive import scan_archive

        surface_index = len(context.surfaces)
        _surface(context, source_chain, "zip", SurfaceStatus.SCANNED, len(data), "archive")
        office_kind = scan_archive(data, source_chain, context, depth=depth)
        if office_kind is not None:
            original = context.surfaces[surface_index]
            context.surfaces[surface_index] = type(original)(
                source_chain=original.source_chain,
                kind=office_kind,
                status=original.status,
                bytes_inspected=original.bytes_inspected,
                scanner="ooxml+archive",
                note=original.note,
            )
        return

    if kind == "text":
        text = decode_text(data, context.limits.max_text_chars)
        if text is None:
            _surface(
                context,
                source_chain,
                "text",
                SurfaceStatus.PARTIAL,
                len(data),
                "text",
                "declared text could not be decoded as UTF-8/UTF-16",
            )
            return
        scan_text(text, source_chain, context)
        note = ""
        status = SurfaceStatus.SCANNED
        if len(text) >= context.limits.max_text_chars:
            status = SurfaceStatus.PARTIAL
            note = "text character limit reached"
        _surface(context, source_chain, "text", status, len(data), "text", note)
        return

    if kind == "pdf":
        scan_pdf(data, source_chain, context)
        scan_text(
            data.decode("latin-1", errors="ignore")[: context.limits.max_text_chars],
            source_chain,
            context,
            location_prefix="uncompressed PDF bytes",
        )
        status = SurfaceStatus.PARTIAL
        note = "objects and uncompressed text scanned; rendered-page OCR is not enabled"
        if b"/Encrypt" in data:
            note = "encrypted PDF content could not be inspected"
        _surface(context, source_chain, "pdf", status, len(data), "pdf", note)
        return

    if kind in {"jpeg", "png", "gif", "tiff", "webp"}:
        scan_image(kind, data, source_chain, context)
        _surface(
            context,
            source_chain,
            kind,
            SurfaceStatus.PARTIAL,
            len(data),
            "image-metadata",
            "container metadata scanned; visual OCR is not enabled",
        )
        return

    if kind == "svg":
        text = decode_text(data, context.limits.max_text_chars)
        if text is not None:
            scan_text(text, source_chain, context)
            truncated = len(text) >= context.limits.max_text_chars
            _surface(
                context,
                source_chain,
                "svg",
                SurfaceStatus.PARTIAL if truncated else SurfaceStatus.SCANNED,
                len(data),
                "text",
                "text character limit reached" if truncated else "",
            )
        else:
            _surface(
                context,
                source_chain,
                "svg",
                SurfaceStatus.PARTIAL,
                len(data),
                "text",
                "SVG text could not be decoded",
            )
        return

    if kind in {"office-ole", "ole"}:
        context.add_finding(
            "SL.SCAN.UNSUPPORTED_CONTENT",
            source_chain,
            "compound binary document",
            kind,
        )
        _surface(
            context,
            source_chain,
            kind,
            SurfaceStatus.SKIPPED,
            0,
            "dispatcher",
            "legacy or encrypted OLE content is unsupported",
        )
        return

    context.add_finding(
        "SL.SCAN.UNSUPPORTED_CONTENT",
        source_chain,
        "content format",
        kind,
    )
    _surface(
        context,
        source_chain,
        kind,
        SurfaceStatus.SKIPPED,
        0,
        "dispatcher",
        "no built-in scanner recognized this content",
    )


def _read_regular_file(
    path: Path,
    source_chain: tuple[str, ...],
    context: ScanContext,
) -> bytes | None:
    try:
        before = path.stat(follow_symlinks=False)
    except OSError:
        context.add_error(source_chain, "SL.SCAN.READ_ERROR", "File metadata could not be read")
        _surface(context, source_chain, "file", SurfaceStatus.SKIPPED, 0, "filesystem")
        return None
    if not stat.S_ISREG(before.st_mode):
        context.add_finding(
            "SL.SCAN.UNSUPPORTED_CONTENT",
            source_chain,
            "filesystem object type",
            "non-regular filesystem object",
        )
        _surface(
            context,
            source_chain,
            "special-file",
            SurfaceStatus.SKIPPED,
            0,
            "filesystem",
            "only regular files are read",
        )
        return None
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        context.add_error(source_chain, "SL.SCAN.READ_ERROR", "File could not be opened safely")
        _surface(context, source_chain, "file", SurfaceStatus.SKIPPED, 0, "filesystem")
        return None
    try:
        with os.fdopen(descriptor, "rb") as handle:
            opened = os.fstat(handle.fileno())
            if not metadata_matches_open_file(before, opened):
                context.add_error(
                    source_chain,
                    "SL.SCAN.READ_ERROR",
                    "File identity changed before it could be read",
                )
                _surface(context, source_chain, "file", SurfaceStatus.SKIPPED, 0, "filesystem")
                return None
            _record_platform_filesystem_coverage(
                path,
                source_chain,
                context,
                is_directory=False,
            )
            current = path.stat(follow_symlinks=False)
            if not metadata_matches_open_file(current, opened):
                context.add_error(
                    source_chain,
                    "SL.SCAN.READ_ERROR",
                    "File identity changed during metadata inspection",
                )
                _surface(context, source_chain, "file", SurfaceStatus.SKIPPED, 0, "filesystem")
                return None
            size = opened.st_size
            if size > context.limits.max_file_bytes:
                context.add_finding(
                    "SL.ARCHIVE.LIMIT_EXCEEDED",
                    source_chain,
                    "top-level file size",
                    f"file size {size} exceeds configured limit",
                )
                _surface(
                    context,
                    source_chain,
                    "file",
                    SurfaceStatus.SKIPPED,
                    0,
                    "filesystem",
                    "file exceeded size limit",
                )
                return None
            read_limit = min(context.limits.max_file_bytes, context.remaining_bytes)
            if read_limit <= 0:
                context.add_finding(
                    "SL.ARCHIVE.LIMIT_EXCEEDED",
                    source_chain,
                    "total scan-byte budget",
                    "configured total byte budget exceeded",
                )
                _surface(
                    context,
                    source_chain,
                    "file",
                    SurfaceStatus.SKIPPED,
                    0,
                    "filesystem",
                    "scan byte budget exhausted",
                )
                return None
            data = handle.read(read_limit + 1)
            after = os.fstat(handle.fileno())
    except OSError:
        context.add_error(source_chain, "SL.SCAN.READ_ERROR", "File content could not be read")
        _surface(context, source_chain, "file", SurfaceStatus.SKIPPED, 0, "filesystem")
        return None
    if _file_state(after) != _file_state(opened):
        context.add_error(
            source_chain, "SL.SCAN.READ_ERROR", "File changed while it was being read"
        )
        _surface(context, source_chain, "file", SurfaceStatus.SKIPPED, len(data), "filesystem")
        return None
    if len(data) > read_limit:
        context.consume(read_limit)
        context.add_finding(
            "SL.ARCHIVE.LIMIT_EXCEEDED",
            source_chain,
            "top-level file read budget",
            "file grew beyond the configured read budget",
        )
        _surface(
            context,
            source_chain,
            "file",
            SurfaceStatus.SKIPPED,
            read_limit,
            "filesystem",
            "file exceeded a runtime read limit",
        )
        return None
    if not context.consume(len(data)):
        # The bounded read above makes this unreachable unless session state is corrupt.
        context.add_error(source_chain, "SL.SCAN.READ_ERROR", "Scan byte accounting failed")
        _surface(context, source_chain, "file", SurfaceStatus.SKIPPED, 0, "filesystem")
        return None
    return data


def scan(
    target: str | os.PathLike[str],
    *,
    limits: ScanLimits | None = None,
    logical_name: str | None = None,
) -> ScanReport:
    path = Path(target)
    try:
        target_metadata = path.stat(follow_symlinks=False)
    except FileNotFoundError as exc:
        raise ScanInputError("target does not exist") from exc
    except OSError as exc:
        raise ScanInputError("target metadata could not be read safely") from exc
    supported_kind = stat.S_ISREG(target_metadata.st_mode) or stat.S_ISDIR(target_metadata.st_mode)
    if not supported_kind and not metadata_is_filesystem_link(target_metadata):
        raise ScanInputError("target is not a regular file or directory")
    context = ScanContext(limits or ScanLimits())
    raw_target_name = logical_name or path.name or "share-boundary"
    target_name = context.display_path(raw_target_name)
    scan_name(raw_target_name, (target_name,), context)
    manifest = hashlib.sha256()

    if metadata_is_filesystem_link(target_metadata):
        context.add_finding(
            "SL.ARCHIVE.SYMLINK",
            (target_name,),
            "top-level filesystem object",
            target_name,
            evidence_kind="path",
        )
        _surface(
            context,
            (target_name,),
            "filesystem-link",
            SurfaceStatus.SKIPPED,
            0,
            "filesystem",
            "symbolic links and Windows reparse points are not followed",
        )
        manifest.update(b"symlink\0")
        target_kind = "symlink"
    elif stat.S_ISREG(target_metadata.st_mode):
        data = _read_regular_file(path, (target_name,), context)
        if data is not None:
            manifest.update(data)
            scan_blob(
                raw_target_name,
                data,
                (target_name,),
                context,
                already_counted=True,
            )
        target_kind = "file"
    elif stat.S_ISDIR(target_metadata.st_mode):
        target_kind = "directory"
        root_is_stable = _record_directory_platform_coverage(
            path,
            (target_name,),
            context,
            target_metadata,
        )
        if root_is_stable:
            items, directories, traversal_errors, entry_limit_reached = bounded_directory_tree(
                path,
                context.limits.max_archive_members,
            )
        else:
            items, directories, traversal_errors, entry_limit_reached = [], [], 0, False
        for index in range(traversal_errors):
            error_chain = (target_name, f"<unreadable-directory:{index + 1}>")
            context.add_error(
                error_chain,
                "SL.SCAN.READ_ERROR",
                "Directory contents could not be enumerated",
            )
            _surface(
                context,
                error_chain,
                "directory",
                SurfaceStatus.SKIPPED,
                0,
                "filesystem",
                "directory enumeration failed",
            )
            manifest.update(b"unreadable-directory\0")
        if entry_limit_reached:
            limit_chain = (target_name, "<filesystem-entry-limit>")
            context.add_finding(
                "SL.ARCHIVE.LIMIT_EXCEEDED",
                limit_chain,
                "filesystem entry count",
                "configured filesystem entry count exceeded",
            )
            _surface(
                context,
                limit_chain,
                "directory",
                SurfaceStatus.PARTIAL,
                0,
                "filesystem",
                "filesystem entry-count limit reached",
            )
            manifest.update(b"filesystem-entry-limit\0")
        for directory in directories:
            relative = directory.relative_to(path).as_posix()
            display_relative = context.display_path(relative)
            source_chain = (target_name, display_relative)
            scan_name(relative, source_chain, context)
            try:
                directory_metadata = directory.stat(follow_symlinks=False)
            except OSError:
                context.add_error(
                    source_chain,
                    "SL.SCAN.READ_ERROR",
                    "Directory metadata could not be read safely",
                )
                _surface(
                    context,
                    source_chain,
                    "directory",
                    SurfaceStatus.SKIPPED,
                    0,
                    "filesystem",
                    "directory metadata could not be inspected",
                )
                continue
            if metadata_is_filesystem_link(directory_metadata) or not stat.S_ISDIR(
                directory_metadata.st_mode
            ):
                context.add_error(
                    source_chain,
                    "SL.SCAN.READ_ERROR",
                    "Directory identity changed before metadata inspection",
                )
                _surface(
                    context,
                    source_chain,
                    "directory",
                    SurfaceStatus.SKIPPED,
                    0,
                    "filesystem",
                    "directory identity changed during traversal",
                )
                continue
            _record_directory_platform_coverage(
                directory,
                source_chain,
                context,
                directory_metadata,
            )
        for item in items:
            relative = item.relative_to(path).as_posix()
            display_relative = context.display_path(relative)
            source_chain = (target_name, display_relative)
            scan_name(relative, source_chain, context)
            manifest.update(_filesystem_name_bytes(relative))
            manifest.update(b"\0")
            try:
                item_metadata = item.stat(follow_symlinks=False)
            except OSError:
                context.add_error(
                    source_chain,
                    "SL.SCAN.READ_ERROR",
                    "Filesystem object metadata could not be read safely",
                )
                _surface(
                    context,
                    source_chain,
                    "filesystem-object",
                    SurfaceStatus.SKIPPED,
                    0,
                    "filesystem",
                    "filesystem object metadata could not be inspected",
                )
                manifest.update(b"unreadable-metadata\0")
                continue
            if metadata_is_filesystem_link(item_metadata):
                context.add_finding(
                    "SL.ARCHIVE.SYMLINK",
                    source_chain,
                    "filesystem object",
                    relative,
                    evidence_kind="path",
                )
                _surface(
                    context,
                    source_chain,
                    "filesystem-link",
                    SurfaceStatus.SKIPPED,
                    0,
                    "filesystem",
                    "symbolic links and Windows reparse points are not followed",
                )
                manifest.update(b"symlink\0")
                continue
            data = _read_regular_file(item, source_chain, context)
            if data is None:
                manifest.update(b"unreadable\0")
                continue
            digest = hashlib.sha256(data).digest()
            manifest.update(len(data).to_bytes(8, "big"))
            manifest.update(digest)
            scan_blob(
                relative,
                data,
                source_chain,
                context,
                already_counted=True,
            )
    else:
        raise ScanInputError("target is not a regular file or directory")

    context.findings.sort(
        key=lambda item: (-item.severity.rank, item.source_chain, item.location, item.rule_id)
    )
    context.surfaces.sort(key=lambda item: (item.source_chain, item.kind, item.scanner))
    context.errors.sort(key=lambda item: (item.source_chain, item.code))
    return ScanReport(
        target_name=target_name,
        target_kind=target_kind,
        target_sha256=manifest.hexdigest(),
        fingerprint_scope=context.protector.scope,
        limits=context.limits,
        findings=context.findings,
        surfaces=context.surfaces,
        errors=context.errors,
    )
