"""Bounded, no-follow reads for explicitly selected local control documents."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from .filesystem import metadata_is_filesystem_link, metadata_matches_open_file


class DocumentInputError(ValueError):
    """A control document cannot be read without violating the input contract."""


def read_document(path: Path, max_bytes: int) -> bytes:
    """Read a stable regular file without following a final-component link.

    Error messages deliberately omit paths, parser excerpts, and source bytes.
    The parent directory is operator-selected, not a hostile sandbox boundary.
    """

    if type(max_bytes) is not int or max_bytes <= 0:
        raise DocumentInputError("document byte limit must be a positive integer")
    descriptor: int | None = None
    try:
        before = path.stat(follow_symlinks=False)
        if metadata_is_filesystem_link(before) or not stat.S_ISREG(before.st_mode):
            raise DocumentInputError("control document must be a regular, non-link file")
        if before.st_size > max_bytes:
            raise DocumentInputError("control document exceeds its byte limit")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        flags |= getattr(os, "O_BINARY", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if not metadata_matches_open_file(before, opened):
            raise DocumentInputError("control document changed while being opened")
        result = bytearray()
        while len(result) <= max_bytes:
            chunk = os.read(descriptor, min(64 * 1024, max_bytes + 1 - len(result)))
            if not chunk:
                break
            result.extend(chunk)
        if len(result) > max_bytes:
            raise DocumentInputError("control document exceeds its byte limit")
        after = os.fstat(descriptor)
        current = path.stat(follow_symlinks=False)
        if (
            not metadata_matches_open_file(before, after)
            or not metadata_matches_open_file(current, after)
            or len(result) != before.st_size
        ):
            raise DocumentInputError("control document changed while being read")
        return bytes(result)
    except OSError as exc:
        raise DocumentInputError("control document could not be read safely") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
