"""Privacy-preserving Windows alternate data stream enumeration.

Only the existence of a named ``$DATA`` stream crosses this module boundary.
Stream names and contents are deliberately never returned, logged, or included
in scan state.
"""

from __future__ import annotations

import ctypes
import os
from collections.abc import Callable
from enum import StrEnum
from typing import Any, Protocol, cast

from .context import ScanContext
from .models import SurfaceStatus

_ERROR_HANDLE_EOF = 38
_ERROR_INVALID_PARAMETER = 87
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
_DEFAULT_DATA_STREAM = "::$DATA"
_STREAM_NAME_CAPACITY = 260 + 36
_MAX_STREAM_RECORDS = 1_024

_ENUMERATION_ERROR_MESSAGE = "Windows alternate data streams could not be enumerated"
_ENUMERATION_ERROR_NOTE = "Windows alternate data stream enumeration failed"
_NAMED_STREAM_NOTE = "named Windows alternate data stream present; content was not inspected"


class WindowsStreamStatus(StrEnum):
    """Privacy-safe result of enumerating one filesystem object's streams."""

    NOT_APPLICABLE = "not-applicable"
    SCANNED = "scanned"
    NAMED_STREAM_PRESENT = "named-stream-present"
    ENUMERATION_ERROR = "enumeration-error"


class _Win32FindStreamData(ctypes.Structure):
    _fields_ = [
        ("stream_size", ctypes.c_longlong),
        ("stream_name", ctypes.c_wchar * _STREAM_NAME_CAPACITY),
    ]


class _StreamApi(Protocol):
    def find_first(self, path: str, data: _Win32FindStreamData) -> int: ...

    def find_next(self, handle: int, data: _Win32FindStreamData) -> bool: ...

    def last_error(self) -> int: ...

    def close(self, handle: int) -> bool: ...


class _Kernel32StreamApi:
    """Narrow, typed wrapper around the Win32 stream-enumeration functions."""

    def __init__(self) -> None:
        loader = getattr(ctypes, "WinDLL", None)
        get_last_error = getattr(ctypes, "get_last_error", None)
        if loader is None or get_last_error is None:
            raise OSError("Win32 stream APIs are unavailable")

        kernel32 = loader("kernel32", use_last_error=True)
        self._find_first: Any = kernel32.FindFirstStreamW
        self._find_first.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_int,
            ctypes.POINTER(_Win32FindStreamData),
            ctypes.c_uint32,
        ]
        self._find_first.restype = ctypes.c_void_p

        self._find_next: Any = kernel32.FindNextStreamW
        self._find_next.argtypes = [ctypes.c_void_p, ctypes.POINTER(_Win32FindStreamData)]
        self._find_next.restype = ctypes.c_int

        self._find_close: Any = kernel32.FindClose
        self._find_close.argtypes = [ctypes.c_void_p]
        self._find_close.restype = ctypes.c_int
        self._get_last_error = cast(Callable[[], int], get_last_error)

    def find_first(self, path: str, data: _Win32FindStreamData) -> int:
        handle = self._find_first(path, 0, ctypes.byref(data), 0)
        return cast(int, handle)

    def find_next(self, handle: int, data: _Win32FindStreamData) -> bool:
        return bool(self._find_next(handle, ctypes.byref(data)))

    def last_error(self) -> int:
        return self._get_last_error()

    def close(self, handle: int) -> bool:
        return bool(self._find_close(handle))


def _contains_named_stream(data: _Win32FindStreamData) -> bool | None:
    """Classify one record without allowing its name to escape."""

    name = cast(str, data.stream_name)
    if not name:
        return None
    return name.casefold() != _DEFAULT_DATA_STREAM.casefold()


def inspect_windows_streams(
    path: str | os.PathLike[str],
    *,
    is_directory: bool,
    _api: _StreamApi | None = None,
) -> WindowsStreamStatus:
    """Return whether a filesystem object has a named Windows data stream.

    The result intentionally carries no stream name, size, content, native error
    text, or numeric error code. ``ERROR_INVALID_PARAMETER`` from the initial
    call means the backing filesystem does not support this enumeration and is
    therefore not an inspection gap.
    """

    if _api is None:
        if os.name != "nt":
            return WindowsStreamStatus.NOT_APPLICABLE
        try:
            _api = _Kernel32StreamApi()
        except Exception:
            return WindowsStreamStatus.ENUMERATION_ERROR

    data = _Win32FindStreamData()
    try:
        handle = _api.find_first(os.path.abspath(os.fspath(path)), data)
    except Exception:
        return WindowsStreamStatus.ENUMERATION_ERROR

    if handle == _INVALID_HANDLE_VALUE:
        try:
            error = _api.last_error()
        except Exception:
            return WindowsStreamStatus.ENUMERATION_ERROR
        if error == _ERROR_HANDLE_EOF:
            return (
                WindowsStreamStatus.SCANNED
                if is_directory
                else WindowsStreamStatus.ENUMERATION_ERROR
            )
        if error == _ERROR_INVALID_PARAMETER:
            return WindowsStreamStatus.NOT_APPLICABLE
        return WindowsStreamStatus.ENUMERATION_ERROR

    result = WindowsStreamStatus.SCANNED
    records_seen = 0
    try:
        while True:
            records_seen += 1
            if records_seen > _MAX_STREAM_RECORDS:
                result = WindowsStreamStatus.ENUMERATION_ERROR
                break
            classification = _contains_named_stream(data)
            if classification is None:
                result = WindowsStreamStatus.ENUMERATION_ERROR
                break
            if classification:
                result = WindowsStreamStatus.NAMED_STREAM_PRESENT
                break
            try:
                has_next = _api.find_next(handle, data)
            except Exception:
                result = WindowsStreamStatus.ENUMERATION_ERROR
                break
            if not has_next:
                try:
                    error = _api.last_error()
                except Exception:
                    result = WindowsStreamStatus.ENUMERATION_ERROR
                else:
                    result = (
                        WindowsStreamStatus.SCANNED
                        if error == _ERROR_HANDLE_EOF
                        else WindowsStreamStatus.ENUMERATION_ERROR
                    )
                break
    finally:
        try:
            closed = _api.close(handle)
        except Exception:
            closed = False

    if not closed and result is not WindowsStreamStatus.NAMED_STREAM_PRESENT:
        return WindowsStreamStatus.ENUMERATION_ERROR
    return result


def record_windows_stream_coverage(
    path: str | os.PathLike[str],
    source_chain: tuple[str, ...],
    context: ScanContext,
    *,
    is_directory: bool,
    _api: _StreamApi | None = None,
) -> WindowsStreamStatus:
    """Record a fixed, privacy-safe coverage outcome for one filesystem object."""

    status = inspect_windows_streams(path, is_directory=is_directory, _api=_api)
    if status is WindowsStreamStatus.NOT_APPLICABLE:
        return status
    if status is WindowsStreamStatus.SCANNED:
        context.add_surface(
            source_chain,
            "windows-alternate-data-streams",
            SurfaceStatus.SCANNED,
            0,
            "windows-streams",
        )
        return status
    if status is WindowsStreamStatus.NAMED_STREAM_PRESENT:
        context.add_finding(
            "SL.FILESYSTEM.ALTERNATE_DATA_STREAM",
            source_chain,
            "Windows alternate data stream",
            "named alternate data stream present",
        )
        context.add_surface(
            source_chain,
            "windows-alternate-data-streams",
            SurfaceStatus.SKIPPED,
            0,
            "windows-streams",
            _NAMED_STREAM_NOTE,
        )
        return status

    context.add_error(source_chain, "SL.SCAN.READ_ERROR", _ENUMERATION_ERROR_MESSAGE)
    context.add_surface(
        source_chain,
        "windows-alternate-data-streams",
        SurfaceStatus.SKIPPED,
        0,
        "windows-streams",
        _ENUMERATION_ERROR_NOTE,
    )
    return status
