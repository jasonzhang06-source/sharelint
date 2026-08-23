"""Bounded filesystem enumeration shared by scanning and packing."""

from __future__ import annotations

import os
from pathlib import Path


def bounded_directory_items(root: Path, limit: int) -> tuple[list[Path], int, bool]:
    """Return non-directory entries without enumerating more than ``limit`` names.

    The result is globally stable-sorted. Directory and metadata failures are
    counted without forwarding platform exception text, and ``limited`` is true
    when another entry existed beyond the configured ceiling.
    """

    result: list[Path] = []
    pending = [root]
    error_count = 0
    entry_count = 0

    while pending:
        current = pending.pop()
        current_entries: list[tuple[str, Path, bool]] = []
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    entry_count += 1
                    if entry_count > limit:
                        return (
                            sorted(result, key=lambda item: item.relative_to(root).as_posix()),
                            error_count,
                            True,
                        )
                    try:
                        is_directory = entry.is_dir(follow_symlinks=False)
                    except OSError:
                        error_count += 1
                        continue
                    current_entries.append((entry.name, Path(entry.path), is_directory))
        except OSError:
            error_count += 1
            continue

        current_entries.sort(key=lambda item: item[0])
        directories: list[Path] = []
        for _name, item, is_directory in current_entries:
            if is_directory:
                directories.append(item)
            else:
                result.append(item)
        pending.extend(reversed(directories))

    return (
        sorted(result, key=lambda item: item.relative_to(root).as_posix()),
        error_count,
        False,
    )
