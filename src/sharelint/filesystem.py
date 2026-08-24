"""Bounded filesystem enumeration shared by scanning and packing."""

from __future__ import annotations

import os
import stat
from pathlib import Path


def metadata_is_reparse_point(metadata: os.stat_result) -> bool:
    """Return whether metadata represents a Windows filesystem reparse point.

    ``Path.is_junction`` is unavailable on the project's minimum Python 3.11.
    ``st_file_attributes`` is present on Windows and absent on POSIX, so this
    remains a dependency-free cross-platform check.
    """

    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(attributes & reparse_flag)


def metadata_is_filesystem_link(metadata: os.stat_result) -> bool:
    """Return whether metadata describes a symbolic link or Windows reparse point."""

    return stat.S_ISLNK(metadata.st_mode) or metadata_is_reparse_point(metadata)


def _directory_identity(metadata: os.stat_result) -> tuple[int, int]:
    return metadata.st_dev, metadata.st_ino


def _stable_directory_metadata(
    path: Path,
    expected_identity: tuple[int, int] | None = None,
) -> os.stat_result | None:
    """Return no-follow metadata only while ``path`` is the expected real directory."""

    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError:
        return None
    if metadata_is_filesystem_link(metadata) or not stat.S_ISDIR(metadata.st_mode):
        return None
    if expected_identity is not None and _directory_identity(metadata) != expected_identity:
        return None
    return metadata


def bounded_directory_tree(
    root: Path,
    limit: int,
) -> tuple[list[Path], list[Path], int, bool]:
    """Return files and real directories without enumerating beyond ``limit`` names.

    Both path lists are globally stable-sorted. Filesystem links are returned in
    the first list so the scanner can report them without following them. Directory
    and metadata failures are counted without forwarding platform exception text,
    and ``limited`` is true when another entry existed beyond the configured ceiling.
    """

    result: list[Path] = []
    visited_directories: list[Path] = []
    root_metadata = _stable_directory_metadata(root)
    if root_metadata is None:
        return [], [], 1, False

    pending = [(root, _directory_identity(root_metadata))]
    error_count = 0
    entry_count = 0

    while pending:
        current, expected_identity = pending.pop()
        if _stable_directory_metadata(current, expected_identity) is None:
            error_count += 1
            continue
        current_entries: list[tuple[str, Path, bool]] = []
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    entry_count += 1
                    if entry_count > limit:
                        return (
                            sorted(result, key=lambda item: item.relative_to(root).as_posix()),
                            sorted(
                                visited_directories,
                                key=lambda item: item.relative_to(root).as_posix(),
                            ),
                            error_count,
                            True,
                        )
                    try:
                        metadata = entry.stat(follow_symlinks=False)
                        is_directory = not metadata_is_filesystem_link(metadata) and stat.S_ISDIR(
                            metadata.st_mode
                        )
                    except OSError:
                        error_count += 1
                        continue
                    current_entries.append((entry.name, current / entry.name, is_directory))
        except OSError:
            error_count += 1
            continue

        if _stable_directory_metadata(current, expected_identity) is None:
            error_count += 1
            continue

        current_entries.sort(key=lambda item: item[0])
        directories: list[tuple[Path, tuple[int, int]]] = []
        for _name, item, is_directory in current_entries:
            if is_directory:
                try:
                    metadata = item.stat(follow_symlinks=False)
                except OSError:
                    error_count += 1
                    continue
                if metadata_is_filesystem_link(metadata) or not stat.S_ISDIR(metadata.st_mode):
                    error_count += 1
                    continue
                directories.append((item, _directory_identity(metadata)))
                visited_directories.append(item)
            else:
                result.append(item)
        pending.extend(reversed(directories))

    return (
        sorted(result, key=lambda item: item.relative_to(root).as_posix()),
        sorted(visited_directories, key=lambda item: item.relative_to(root).as_posix()),
        error_count,
        False,
    )


def bounded_directory_items(root: Path, limit: int) -> tuple[list[Path], int, bool]:
    """Return non-directory entries while preserving the original public helper contract."""

    items, _directories, errors, limited = bounded_directory_tree(root, limit)
    return items, errors, limited
