"""Presence-only probes for POSIX extended filesystem attributes.

The probes deliberately request only the size of the platform attribute-name
list.  Attribute names and values are never copied into Python memory or
included in a report.
"""

from __future__ import annotations

import ctypes
import os
import sys
from enum import StrEnum
from pathlib import Path


class ExtendedAttributeStatus(StrEnum):
    """Privacy-safe result of an extended-attribute presence probe."""

    NOT_APPLICABLE = "not-applicable"
    ABSENT = "absent"
    PRESENT = "present"
    ERROR = "error"


EXTENDED_ATTRIBUTE_ERROR_MESSAGE = "Extended attributes could not be enumerated"


def _linux_name_list_size(path: Path) -> int:
    """Return the Linux xattr name-list size without retrieving the names."""

    library = ctypes.CDLL(None, use_errno=True)
    function = library.llistxattr
    function.argtypes = (ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t)
    function.restype = ctypes.c_ssize_t
    ctypes.set_errno(0)
    return int(function(os.fsencode(path), None, 0))


def _macos_name_list_size(path: Path) -> int:
    """Return the macOS xattr name-list size without retrieving the names."""

    library = ctypes.CDLL(None, use_errno=True)
    function = library.listxattr
    function.argtypes = (ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int)
    function.restype = ctypes.c_ssize_t
    xattr_nofollow = 0x0001
    ctypes.set_errno(0)
    return int(function(os.fsencode(path), None, 0, xattr_nofollow))


def probe_extended_attributes(path: Path) -> ExtendedAttributeStatus:
    """Detect xattr presence without retrieving attribute names or values.

    Linux uses ``llistxattr`` and macOS uses ``listxattr`` with
    ``XATTR_NOFOLLOW``.  Both calls receive a null name buffer and a zero
    buffer size.  Operational failures collapse to one fixed status so raw
    platform exception text cannot enter reports.
    """

    try:
        if sys.platform.startswith("linux"):
            size = _linux_name_list_size(path)
        elif sys.platform == "darwin":
            size = _macos_name_list_size(path)
        else:
            return ExtendedAttributeStatus.NOT_APPLICABLE
    except (AttributeError, ctypes.ArgumentError, OSError, OverflowError, TypeError, ValueError):
        return ExtendedAttributeStatus.ERROR
    if size < 0:
        return ExtendedAttributeStatus.ERROR
    if size > 0:
        return ExtendedAttributeStatus.PRESENT
    return ExtendedAttributeStatus.ABSENT
