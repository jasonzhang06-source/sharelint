#!/usr/bin/env python3
"""Build a self-contained ShareLint executable and deterministic release archive."""

from __future__ import annotations

import argparse
import ast
import fnmatch
import gzip
import hashlib
import importlib
import importlib.metadata
import io
import json
import os
import platform
import re
import subprocess
import sys
import sysconfig
import tarfile
import tempfile
import zipfile
import zlib
from dataclasses import asdict, dataclass
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
BUILD_LOCKS = (
    REPOSITORY_ROOT / "requirements" / "release-build.txt",
    REPOSITORY_ROOT / "requirements" / "standalone-build.txt",
)
FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)
SAFE_VERSION = re.compile(r"\A[0-9A-Za-z][0-9A-Za-z.+_-]*\Z")
PORTABLE_PYTHON_VERSION = "3.13.15"
LICENSE_CATALOG = REPOSITORY_ROOT / "scripts" / "native-license-catalog.json"
THIRD_PARTY_NOTICES = REPOSITORY_ROOT / "scripts" / "THIRD-PARTY-NOTICES.txt"
MAX_NATIVE_FILE_BYTES = 128 * 1024 * 1024
MAX_NATIVE_TOTAL_BYTES = 512 * 1024 * 1024
MAX_TOC_BYTES = 16 * 1024 * 1024
MAX_TOC_ENTRIES = 10_000
MAX_NATIVE_FILES = 2_048

# Exact runtime files observed with the locked Windows toolchain. Do not accept
# arbitrary DLLs by prefix: new runtime entries require a catalog review.
WINDOWS_MICROSOFT_RUNTIME = frozenset(
    [
        "vcruntime140.dll",
        "ucrtbase.dll",
        "api-ms-win-core-console-l1-1-0.dll",
        "api-ms-win-core-datetime-l1-1-0.dll",
        "api-ms-win-core-debug-l1-1-0.dll",
        "api-ms-win-core-errorhandling-l1-1-0.dll",
        "api-ms-win-core-fibers-l1-1-0.dll",
        "api-ms-win-core-fibers-l1-1-1.dll",
        "api-ms-win-core-file-l1-1-0.dll",
        "api-ms-win-core-file-l1-2-0.dll",
        "api-ms-win-core-file-l2-1-0.dll",
        "api-ms-win-core-handle-l1-1-0.dll",
        "api-ms-win-core-heap-l1-1-0.dll",
        "api-ms-win-core-interlocked-l1-1-0.dll",
        "api-ms-win-core-kernel32-legacy-l1-1-1.dll",
        "api-ms-win-core-libraryloader-l1-1-0.dll",
        "api-ms-win-core-localization-l1-2-0.dll",
        "api-ms-win-core-memory-l1-1-0.dll",
        "api-ms-win-core-namedpipe-l1-1-0.dll",
        "api-ms-win-core-processenvironment-l1-1-0.dll",
        "api-ms-win-core-processthreads-l1-1-0.dll",
        "api-ms-win-core-processthreads-l1-1-1.dll",
        "api-ms-win-core-profile-l1-1-0.dll",
        "api-ms-win-core-rtlsupport-l1-1-0.dll",
        "api-ms-win-core-string-l1-1-0.dll",
        "api-ms-win-core-synch-l1-1-0.dll",
        "api-ms-win-core-synch-l1-2-0.dll",
        "api-ms-win-core-sysinfo-l1-1-0.dll",
        "api-ms-win-core-sysinfo-l1-2-0.dll",
        "api-ms-win-core-timezone-l1-1-0.dll",
        "api-ms-win-core-util-l1-1-0.dll",
        "api-ms-win-crt-conio-l1-1-0.dll",
        "api-ms-win-crt-convert-l1-1-0.dll",
        "api-ms-win-crt-environment-l1-1-0.dll",
        "api-ms-win-crt-filesystem-l1-1-0.dll",
        "api-ms-win-crt-heap-l1-1-0.dll",
        "api-ms-win-crt-locale-l1-1-0.dll",
        "api-ms-win-crt-math-l1-1-0.dll",
        "api-ms-win-crt-process-l1-1-0.dll",
        "api-ms-win-crt-runtime-l1-1-0.dll",
        "api-ms-win-crt-stdio-l1-1-0.dll",
        "api-ms-win-crt-string-l1-1-0.dll",
        "api-ms-win-crt-time-l1-1-0.dll",
        "api-ms-win-crt-utility-l1-1-0.dll",
    ]
)


class PortableBuildError(RuntimeError):
    """Raised when a portable build cannot be made safely or unambiguously."""


@dataclass(frozen=True)
class PortableTarget:
    slug: str
    executable_name: str
    archive_suffix: str


@dataclass(frozen=True)
class ArchiveMember:
    name: str
    data: bytes
    mode: int = 0o644


@dataclass(frozen=True)
class NativeFileIdentity:
    name: str
    sha256: str
    size: int
    typecode: str = "b"


@dataclass(frozen=True)
class StaticComponentEvidence:
    component: str
    match: str
    origin: str
    version: str


@dataclass(frozen=True)
class NativeRuntimeInventory:
    """Native files frozen into the executable and their reviewed component map."""

    files: tuple[str, ...]
    components: tuple[str, ...]
    identities: tuple[NativeFileIdentity, ...] = ()
    static_components: tuple[StaticComponentEvidence, ...] = ()
    analysis_inventory_sha256: str = ""
    package_inventory_sha256: str = ""


def detect_target(
    *,
    system: str | None = None,
    machine: str | None = None,
    libc_name: str | None = None,
) -> PortableTarget:
    """Return the narrowly supported release target for the current host."""

    detected_system = (system or platform.system()).lower()
    detected_machine = (machine or platform.machine()).lower()
    if detected_system == "linux":
        detected_libc = (libc_name if libc_name is not None else platform.libc_ver()[0]).lower()
        if detected_machine in {"x86_64", "amd64"} and detected_libc == "glibc":
            return PortableTarget("linux-glibc-x86_64", "sharelint", ".tar.gz")
        raise PortableBuildError(
            "standalone Linux releases currently require glibc on x86_64; "
            f"detected {detected_libc or 'unknown-libc'} on {detected_machine or 'unknown-cpu'}"
        )
    if detected_system == "windows" and detected_machine in {"amd64", "x86_64"}:
        return PortableTarget("windows-x86_64", "sharelint.exe", ".zip")
    if detected_system == "darwin" and detected_machine in {"x86_64", "amd64"}:
        return PortableTarget("macos-x86_64", "sharelint", ".tar.gz")
    if detected_system == "darwin" and detected_machine in {"arm64", "aarch64"}:
        return PortableTarget("macos-arm64", "sharelint", ".tar.gz")
    raise PortableBuildError(
        "no standalone release target is defined for "
        f"{detected_system or 'unknown-os'} on {detected_machine or 'unknown-cpu'}"
    )


def _validate_member(member: ArchiveMember, root_name: str) -> None:
    path = Path(member.name)
    if (
        not member.name.startswith(root_name + "/")
        or path.is_absolute()
        or "\\" in member.name
        or ".." in path.parts
        or member.mode not in {0o644, 0o755}
    ):
        raise PortableBuildError(f"unsafe portable archive member: {member.name!r}")


def _prepare_destination(destination: Path) -> Path:
    if destination.exists() or destination.is_symlink():
        raise PortableBuildError(f"refusing to overwrite {destination.name}")
    if not destination.parent.is_dir() or destination.parent.is_symlink():
        raise PortableBuildError("portable output directory must be a real existing directory")
    with tempfile.NamedTemporaryFile(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent, delete=False
    ) as handle:
        temporary = Path(handle.name)
    return temporary


def _commit_temporary(temporary: Path, destination: Path, *, mode: int = 0o644) -> None:
    try:
        if os.name == "posix":
            temporary.chmod(mode)
        os.link(temporary, destination)
    except OSError as exc:
        raise PortableBuildError(f"could not publish {destination.name} atomically") from exc
    finally:
        temporary.unlink(missing_ok=True)


def _write_zip(destination: Path, root_name: str, members: tuple[ArchiveMember, ...]) -> None:
    temporary = _prepare_destination(destination)
    try:
        with zipfile.ZipFile(
            temporary, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
        ) as archive:
            for member in sorted(members, key=lambda item: item.name):
                _validate_member(member, root_name)
                info = zipfile.ZipInfo(member.name, FIXED_ZIP_TIME)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.create_system = 3
                info.external_attr = (0o100000 | member.mode) << 16
                info.flag_bits |= 0x800
                archive.writestr(
                    info,
                    member.data,
                    compress_type=zipfile.ZIP_DEFLATED,
                    compresslevel=9,
                )
        _commit_temporary(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def _write_tar_gz(destination: Path, root_name: str, members: tuple[ArchiveMember, ...]) -> None:
    temporary = _prepare_destination(destination)
    try:
        with (
            temporary.open("wb") as raw,
            gzip.GzipFile(filename="", mode="wb", fileobj=raw, compresslevel=9, mtime=0) as zipped,
            tarfile.open(fileobj=zipped, mode="w", format=tarfile.USTAR_FORMAT) as archive,
        ):
            for member in sorted(members, key=lambda item: item.name):
                _validate_member(member, root_name)
                info = tarfile.TarInfo(member.name)
                info.size = len(member.data)
                info.mode = member.mode
                info.mtime = 0
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                archive.addfile(info, io.BytesIO(member.data))
            raw.flush()
            os.fsync(raw.fileno())
        _commit_temporary(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def _write_bytes_exclusive(destination: Path, content: bytes, *, mode: int = 0o644) -> None:
    temporary = _prepare_destination(destination)
    try:
        with temporary.open("wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        _commit_temporary(temporary, destination, mode=mode)
    finally:
        temporary.unlink(missing_ok=True)


def _find_python_license() -> Path:
    roots = {
        Path(sys.base_prefix),
        Path(sys.prefix),
        Path(sys.executable).resolve().parent,
        Path(sys.executable).resolve().parent.parent,
    }
    configured_prefix = sysconfig.get_config_var("prefix")
    if configured_prefix:
        roots.add(Path(configured_prefix))
    standard_library = sysconfig.get_path("stdlib")
    if standard_library:
        roots.add(Path(standard_library))
    for root in sorted(roots, key=str):
        for name in ("LICENSE.txt", "LICENSE", "LICENSE.rst"):
            candidate = root / name
            if candidate.is_file() and not candidate.is_symlink():
                content = candidate.read_bytes()
                if b"PYTHON SOFTWARE FOUNDATION LICENSE VERSION 2" in content.upper():
                    return candidate
    raise PortableBuildError(
        "the build interpreter license was not found; use an official Python distribution "
        "that ships LICENSE.txt"
    )


def _find_pyinstaller_license() -> Path:
    try:
        distribution = importlib.metadata.distribution("pyinstaller")
    except importlib.metadata.PackageNotFoundError as exc:
        raise PortableBuildError("install the locked 'standalone' build extra first") from exc
    for item in distribution.files or ():
        normalized = str(item).replace("\\", "/")
        if normalized.endswith(".dist-info/licenses/COPYING.txt"):
            candidate = Path(str(distribution.locate_file(item)))
            if candidate.is_file() and not candidate.is_symlink():
                return candidate
    raise PortableBuildError("the installed PyInstaller distribution did not include COPYING.txt")


def _license_catalog() -> dict[str, object]:
    if LICENSE_CATALOG.is_symlink() or not LICENSE_CATALOG.is_file():
        raise PortableBuildError("native license catalog is missing or unsafe")
    try:
        payload = json.loads(LICENSE_CATALOG.read_bytes())
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PortableBuildError("native license catalog is not valid UTF-8 JSON") from exc
    if not isinstance(payload, dict) or set(payload) != {
        "components",
        "format_version",
        "target_static_rules",
    }:
        raise PortableBuildError("native license catalog root is invalid")
    components = payload.get("components")
    rules = payload.get("target_static_rules")
    expected_targets = {
        "linux-glibc-x86_64",
        "windows-x86_64",
        "macos-x86_64",
        "macos-arm64",
    }
    if payload.get("format_version") != 2 or not isinstance(components, dict):
        raise PortableBuildError("native license catalog schema is unsupported")
    if not isinstance(rules, dict) or set(rules) != expected_targets:
        raise PortableBuildError("native license catalog target set is invalid")
    if THIRD_PARTY_NOTICES.is_symlink() or not THIRD_PARTY_NOTICES.is_file():
        raise PortableBuildError("third-party notices are missing or unsafe")
    notices = THIRD_PARTY_NOTICES.read_bytes()
    component_versions: dict[str, set[str]] = {}
    markers: set[str] = set()
    for component, record in components.items():
        if (
            not isinstance(component, str)
            or not component.isascii()
            or not isinstance(record, dict)
            or set(record) != {"sources", "spdx"}
            or not isinstance(record.get("spdx"), str)
            or not record["spdx"]
            or not isinstance(record.get("sources"), list)
            or not record["sources"]
            or len(record["sources"]) > 16
        ):
            raise PortableBuildError("native license catalog component record is invalid")
        component_versions[component] = set()
        for source in record["sources"]:
            if (
                not isinstance(source, dict)
                or set(source) != {"notice_marker", "source_url", "version"}
                or not all(isinstance(source[key], str) and source[key] for key in source)
                or not source["source_url"].startswith("https://")
                or len(source["notice_marker"]) > 256
                or len(source["source_url"]) > 512
                or len(source["version"]) > 64
                or source["notice_marker"] in markers
                or source["notice_marker"].encode("utf-8") not in notices
            ):
                raise PortableBuildError("native license catalog source record is invalid")
            markers.add(source["notice_marker"])
            component_versions[component].add(source["version"])
    for target, target_rules in rules.items():
        if not isinstance(target, str) or not isinstance(target_rules, list):
            raise PortableBuildError("native license catalog rule list is invalid")
        for rule in target_rules:
            if (
                not isinstance(rule, dict)
                or set(rule) != {"component", "match", "origin", "version"}
                or not all(isinstance(rule[key], str) and rule[key] for key in rule)
                or rule["component"] not in components
                or rule["version"] not in component_versions[rule["component"]]
                or "/" in rule["match"]
                or "\\" in rule["match"]
            ):
                raise PortableBuildError("native license catalog static rule is invalid")
    return payload


def _static_component_evidence(
    files: tuple[str, ...], target: str, catalog: dict[str, object]
) -> tuple[StaticComponentEvidence, ...]:
    rules = catalog["target_static_rules"]
    if not isinstance(rules, dict) or not isinstance(rules.get(target), list):
        raise PortableBuildError("native license catalog lacks the selected target")
    basenames = tuple(name.rsplit("/", 1)[-1] for name in files)
    matched: set[StaticComponentEvidence] = set()
    for raw in rules[target]:
        if not isinstance(raw, dict):
            raise PortableBuildError("native license catalog static rule is malformed")
        pattern = raw["match"]
        if pattern == "@always" or any(fnmatch.fnmatchcase(name, pattern) for name in basenames):
            matched.add(
                StaticComponentEvidence(
                    component=raw["component"],
                    match=pattern,
                    origin=raw["origin"],
                    version=raw["version"],
                )
            )
    return tuple(
        sorted(matched, key=lambda item: (item.component, item.version, item.origin, item.match))
    )


def _native_component(name: str, target: str) -> str | None:
    """Map one PyInstaller binary entry to a notice-covered runtime component."""

    if (
        not name
        or name.startswith("/")
        or "\\" in name
        or ".." in Path(name).parts
        or not name.isascii()
    ):
        return None
    lowered = name.lower()
    basename = lowered.rsplit("/", 1)[-1]
    if target == "windows-x86_64" and "/" not in lowered:
        if lowered in WINDOWS_MICROSOFT_RUNTIME:
            return "microsoft-runtime"
        if lowered == "base_library.zip":
            # PyInstaller encodes executable DATA as `b`. Windows X_OK is true
            # for this generated standard-library ZIP; it is not a native DLL.
            return "cpython"
    if "/lib-dynload/" in f"/{lowered}" and basename.endswith((".so", ".dylib", ".pyd")):
        return "cpython"
    if target == "windows-x86_64" and "/" not in lowered and basename.endswith(".pyd"):
        return "cpython"
    if target == "linux-glibc-x86_64" and re.fullmatch(r"libpython3\.13\.so(?:\.\d+)*", basename):
        return "cpython"
    if target.startswith("macos-") and (
        basename == "python" or re.fullmatch(r"libpython3\.13(?:\.\d+)*\.dylib", basename)
    ):
        return "cpython"
    if target == "windows-x86_64" and basename in {"python3.dll", "python313.dll"}:
        return "cpython"
    if target == "linux-glibc-x86_64":
        if basename.startswith(("libbz2.", "libbz2-")):
            return "bzip2"
        if basename.startswith(("libcrypto.", "libcrypto-", "libssl.", "libssl-")):
            return "openssl"
        if basename.startswith(("libffi.", "libffi-")):
            return "libffi"
        if basename.startswith(("liblzma.", "liblzma-")):
            return "xz-utils"
        if basename.startswith("libz."):
            return "zlib"
    if target == "windows-x86_64":
        if basename.startswith(("libcrypto-3", "libssl-3")) and basename.endswith(".dll"):
            return "openssl"
        if basename == "libffi-8.dll":
            return "libffi"
    if target.startswith("macos-") and basename in {"libcrypto.3.dylib", "libssl.3.dylib"}:
        return "openssl"
    return None


def classify_native_runtime(files: tuple[str, ...], target: str) -> NativeRuntimeInventory:
    """Validate a complete frozen binary inventory, failing on unlicensed additions."""

    if target not in {
        "linux-glibc-x86_64",
        "windows-x86_64",
        "macos-x86_64",
        "macos-arm64",
    }:
        raise PortableBuildError(f"unknown native inventory target: {target}")
    if not files or files != tuple(sorted(set(files))):
        raise PortableBuildError(
            "native runtime file inventory must be non-empty, sorted, and unique"
        )
    catalog = _license_catalog()
    catalog_components = catalog["components"]
    if not isinstance(catalog_components, dict):
        raise PortableBuildError("native license catalog component map is invalid")
    classified: dict[str, str] = {}
    unknown: list[str] = []
    for name in files:
        component = _native_component(name, target)
        if component is None:
            unknown.append(name)
        else:
            classified[name] = component
    if unknown:
        raise PortableBuildError(
            "frozen executable contains native files without a reviewed license mapping: "
            + ", ".join(repr(name) for name in unknown)
        )
    static_components = _static_component_evidence(files, target, catalog)
    components = tuple(
        sorted(set(classified.values()) | {item.component for item in static_components})
    )
    if any(component not in catalog_components for component in components):
        raise PortableBuildError("native component lacks a reviewed license catalog entry")
    if "cpython" not in components:
        raise PortableBuildError("frozen executable lacks a recognized CPython runtime")
    return NativeRuntimeInventory(
        files=files,
        components=components,
        static_components=static_components,
    )


def _native_inventory_digest(records: tuple[tuple[str, str], ...]) -> str:
    payload = [{"name": name, "type": kind} for name, kind in records]
    canonical = json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


def _valid_native_name(name: str) -> bool:
    path = Path(name)
    return bool(
        name
        and len(name) <= 512
        and name.isascii()
        and not path.is_absolute()
        and "\\" not in name
        and "." not in path.parts
        and ".." not in path.parts
        and all(part for part in path.parts)
    )


def _read_toc_native_inventory(
    path: Path,
    *,
    inventory_index: int,
    expected_tuple_length: int,
    data_inventory_index: int | None = None,
    include_executable_data: bool = False,
) -> tuple[tuple[str, ...], str]:
    """Read a bounded PyInstaller TOC without retaining host source paths."""

    if path.is_symlink() or not path.is_file():
        raise PortableBuildError(f"PyInstaller inventory is missing or unsafe: {path.name}")
    size = path.stat().st_size
    if size <= 0 or size > MAX_TOC_BYTES:
        raise PortableBuildError(f"PyInstaller inventory exceeds its budget: {path.name}")
    try:
        value = ast.literal_eval(path.read_text(encoding="utf-8"))
    except (
        OSError,
        UnicodeDecodeError,
        SyntaxError,
        ValueError,
        MemoryError,
        RecursionError,
    ) as exc:
        raise PortableBuildError(f"PyInstaller inventory is malformed: {path.name}") from exc
    if not isinstance(value, tuple) or len(value) != expected_tuple_length:
        raise PortableBuildError(f"PyInstaller inventory schema is unexpected: {path.name}")
    entries = value[inventory_index]
    if not isinstance(entries, list) or len(entries) > MAX_TOC_ENTRIES:
        raise PortableBuildError(f"PyInstaller inventory entry list is invalid: {path.name}")
    if data_inventory_index is not None:
        data_entries = value[data_inventory_index]
        if not isinstance(data_entries, list) or len(data_entries) > MAX_TOC_ENTRIES:
            raise PortableBuildError(f"PyInstaller data inventory is invalid: {path.name}")
        entries = entries + data_entries
        if len(entries) > MAX_TOC_ENTRIES:
            raise PortableBuildError(f"PyInstaller combined inventory is too large: {path.name}")
    records: list[tuple[str, str]] = []
    for entry in entries:
        if not isinstance(entry, tuple) or len(entry) != 3:
            raise PortableBuildError(f"PyInstaller inventory entry is malformed: {path.name}")
        destination, source, kind = entry
        if not isinstance(destination, str) or not isinstance(kind, str):
            raise PortableBuildError(f"PyInstaller inventory entry is malformed: {path.name}")
        executable_data = (
            include_executable_data
            and kind == "DATA"
            and isinstance(source, str)
            and os.access(source, os.X_OK)
        )
        if kind not in {"BINARY", "EXTENSION"} and not executable_data:
            continue
        if (
            not isinstance(source, str)
            or not source
            or len(source) > 4096
            or not _valid_native_name(destination)
        ):
            raise PortableBuildError(f"PyInstaller native inventory entry is unsafe: {path.name}")
        records.append((destination, kind))
    ordered = tuple(sorted(records))
    names = tuple(name for name, _ in ordered)
    if not names or len(names) > MAX_NATIVE_FILES or len(set(names)) != len(names):
        raise PortableBuildError(f"PyInstaller native inventory is incomplete: {path.name}")
    return names, _native_inventory_digest(ordered)


def _read_native_runtime(
    executable: Path,
    target: PortableTarget,
    *,
    build_root: Path | None = None,
) -> NativeRuntimeInventory:
    """Read PyInstaller's generated CArchive and classify every native binary entry."""

    if executable.is_symlink() or not executable.is_file():
        raise PortableBuildError("frozen executable is missing or unsafe")
    executable_size = executable.stat().st_size
    if executable_size <= 0 or executable_size > MAX_NATIVE_TOTAL_BYTES:
        raise PortableBuildError("frozen executable exceeds its inspection budget")
    try:
        readers = importlib.import_module("PyInstaller.archive.readers")
        reader = readers.CArchiveReader(str(executable))
        toc = reader.toc
    except (ImportError, OSError, RuntimeError, ValueError) as exc:
        raise PortableBuildError("could not inspect the frozen executable inventory") from exc
    if not isinstance(toc, dict) or len(toc) > MAX_TOC_ENTRIES:
        raise PortableBuildError("frozen executable returned an invalid inventory")
    identities: list[NativeFileIdentity] = []
    total = 0
    for name, entry in toc.items():
        if not isinstance(name, str) or not isinstance(entry, tuple) or len(entry) != 5:
            raise PortableBuildError("frozen executable returned a malformed inventory entry")
        offset, compressed_size, uncompressed_size, compressed, typecode = entry
        if (
            not isinstance(offset, int)
            or isinstance(offset, bool)
            or offset < 0
            or not isinstance(compressed_size, int)
            or isinstance(compressed_size, bool)
            or compressed_size < 0
            or not isinstance(uncompressed_size, int)
            or isinstance(uncompressed_size, bool)
            or uncompressed_size < 0
            or compressed not in {0, 1}
            or isinstance(compressed, bool)
            or not isinstance(typecode, str)
            or len(typecode) != 1
        ):
            raise PortableBuildError("frozen executable returned invalid inventory metadata")
        if typecode != "b":
            continue
        if (
            compressed_size <= 0
            or uncompressed_size <= 0
            or not _valid_native_name(name)
            or uncompressed_size > MAX_NATIVE_FILE_BYTES
        ):
            raise PortableBuildError("frozen executable native file exceeds its safety contract")
        total += uncompressed_size
        if total > MAX_NATIVE_TOTAL_BYTES or len(identities) >= MAX_NATIVE_FILES:
            raise PortableBuildError("frozen executable native inventory exceeds its budget")
        try:
            content = reader.extract(name)
        except (KeyError, OSError, RuntimeError, TypeError, ValueError, zlib.error) as exc:
            raise PortableBuildError("could not extract a frozen native file for hashing") from exc
        if not isinstance(content, bytes) or len(content) != uncompressed_size:
            raise PortableBuildError("frozen native file size differs from its inventory")
        identities.append(
            NativeFileIdentity(
                name=name,
                sha256=hashlib.sha256(content).hexdigest(),
                size=len(content),
                typecode=typecode,
            )
        )
    identities.sort(key=lambda item: item.name)
    files = tuple(item.name for item in identities)
    if len(set(files)) != len(files):
        raise PortableBuildError("frozen executable native inventory contains duplicate names")
    classified = classify_native_runtime(files, target.slug)

    analysis_digest = ""
    package_digest = ""
    if build_root is not None:
        work = build_root / "work" / "sharelint"
        analysis_names, analysis_digest = _read_toc_native_inventory(
            work / "Analysis-00.toc",
            inventory_index=15,
            expected_tuple_length=20,
            data_inventory_index=18,
            include_executable_data=True,
        )
        package_names, package_digest = _read_toc_native_inventory(
            work / "PKG-00.toc",
            inventory_index=2,
            expected_tuple_length=11,
            include_executable_data=True,
        )
        if (
            analysis_names != package_names
            or analysis_names != files
            or analysis_digest != package_digest
        ):
            raise PortableBuildError(
                "PyInstaller Analysis, package, and final executable inventories differ"
            )
    return NativeRuntimeInventory(
        files=classified.files,
        components=classified.components,
        identities=tuple(identities),
        static_components=classified.static_components,
        analysis_inventory_sha256=analysis_digest,
        package_inventory_sha256=package_digest,
    )


def _render_portable_readme(template: Path, *, version: str, target: PortableTarget) -> bytes:
    content = template.read_text(encoding="utf-8")
    run_prefix = r".\sharelint.exe" if target.executable_name.endswith(".exe") else "./sharelint"
    replacements = {
        "@ARCHIVE@": f"sharelint-v{version}-{target.slug}{target.archive_suffix}",
        "@VERSION@": version,
        "@TARGET@": target.slug,
        "@RUN_PREFIX@": run_prefix,
        "@EXECUTABLE@": target.executable_name,
    }
    for marker, value in replacements.items():
        content = content.replace(marker, value)
    if re.search(r"@[A-Z_]+@", content):
        raise PortableBuildError("portable README contains an unresolved template marker")
    return content.encode("utf-8")


def _build_frozen_executable(target: PortableTarget, build_root: Path) -> Path:
    entry = REPOSITORY_ROOT / "scripts" / "standalone_entry.py"
    if not entry.is_file() or entry.is_symlink():
        raise PortableBuildError("standalone entry point is missing or unsafe")
    environment = os.environ.copy()
    environment.pop("PYTHONHOME", None)
    environment.pop("PYTHONPATH", None)
    environment.setdefault("PYTHONHASHSEED", "0")
    environment.setdefault("SOURCE_DATE_EPOCH", "0")
    command = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onefile",
        "--console",
        "--noupx",
        "--log-level",
        "WARN",
        "--python-option",
        "X utf8=1",
        "--name",
        "sharelint",
        "--distpath",
        str(build_root / "dist"),
        "--workpath",
        str(build_root / "work"),
        "--specpath",
        str(build_root / "spec"),
        str(entry),
    ]
    try:
        subprocess.run(command, cwd=build_root, env=environment, check=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise PortableBuildError("PyInstaller failed to build the standalone executable") from exc
    executable = build_root / "dist" / target.executable_name
    if not executable.is_file() or executable.is_symlink() or executable.stat().st_size == 0:
        raise PortableBuildError("PyInstaller did not produce the expected executable")
    return executable


def _installed_version() -> str:
    try:
        version = importlib.metadata.version("sharelint")
    except importlib.metadata.PackageNotFoundError as exc:
        raise PortableBuildError("install the built ShareLint wheel before freezing it") from exc
    if not SAFE_VERSION.fullmatch(version):
        raise PortableBuildError("installed ShareLint version is unsafe for an archive name")
    return version


def _build_info(
    executable: bytes,
    target: PortableTarget,
    version: str,
    native_runtime: NativeRuntimeInventory,
    third_party_notices: bytes,
) -> bytes:
    classified = classify_native_runtime(native_runtime.files, target.slug)
    if (
        not native_runtime.identities
        or tuple(item.name for item in native_runtime.identities) != native_runtime.files
        or any(
            item.typecode != "b"
            or item.size <= 0
            or item.size > MAX_NATIVE_FILE_BYTES
            or re.fullmatch(r"[0-9a-f]{64}", item.sha256) is None
            for item in native_runtime.identities
        )
        or classified.components != native_runtime.components
        or classified.static_components != native_runtime.static_components
        or re.fullmatch(r"[0-9a-f]{64}", native_runtime.analysis_inventory_sha256) is None
        or re.fullmatch(r"[0-9a-f]{64}", native_runtime.package_inventory_sha256) is None
    ):
        raise PortableBuildError("native build inventory is incomplete or inconsistent")
    lock_hasher = hashlib.sha256()
    for lock in BUILD_LOCKS:
        if not lock.is_file() or lock.is_symlink():
            raise PortableBuildError("a required build lock file is missing or unsafe")
        lock_hasher.update(lock.name.encode("ascii") + b"\0" + lock.read_bytes())
    component_names = (
        "altgraph",
        "build",
        "colorama",
        "macholib",
        "packaging",
        "pefile",
        "pip",
        "pyinstaller",
        "pyinstaller-hooks-contrib",
        "pyproject-hooks",
        "pywin32-ctypes",
        "setuptools",
        "sharelint",
    )
    components: dict[str, str] = {}
    for name in component_names:
        try:
            components[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            continue
    required = {"pyinstaller", "pyinstaller-hooks-contrib", "sharelint"}
    if not required.issubset(components):
        raise PortableBuildError("the frozen component inventory is incomplete")
    payload = {
        "build_components": components,
        "build_lock_sha256": lock_hasher.hexdigest(),
        "executable_sha256": hashlib.sha256(executable).hexdigest(),
        "format_version": 2,
        "license_catalog_sha256": hashlib.sha256(LICENSE_CATALOG.read_bytes()).hexdigest(),
        "native_runtime": {
            "analysis_inventory_sha256": native_runtime.analysis_inventory_sha256,
            "components": list(native_runtime.components),
            "files": [asdict(item) for item in native_runtime.identities],
            "package_inventory_sha256": native_runtime.package_inventory_sha256,
            "static_components": [asdict(item) for item in native_runtime.static_components],
        },
        "python": {
            "implementation": platform.python_implementation(),
            "version": platform.python_version(),
        },
        "sharelint_version": version,
        "target": target.slug,
        "third_party_notices_sha256": hashlib.sha256(third_party_notices).hexdigest(),
    }
    return (json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()


def build_portable(output_dir: Path) -> tuple[Path, Path, Path]:
    """Build and return ``(executable, archive, checksum)`` without overwriting files."""

    if (
        platform.python_implementation() != "CPython"
        or platform.python_version() != PORTABLE_PYTHON_VERSION
        or sys.maxsize <= 2**32
        or sys.implementation.cache_tag != "cpython-313"
        or bool(sysconfig.get_config_var("Py_GIL_DISABLED"))
    ):
        raise PortableBuildError(
            "portable releases must be built with the locked "
            f"CPython {PORTABLE_PYTHON_VERSION} toolchain"
        )
    target = detect_target()
    version = _installed_version()
    if output_dir.is_symlink():
        raise PortableBuildError("portable output directory must not be a symbolic link")
    output_dir.mkdir(parents=True, exist_ok=True)
    output_dir = output_dir.resolve()
    if not output_dir.is_dir() or any(output_dir.iterdir()):
        raise PortableBuildError("portable output directory must be empty")

    with tempfile.TemporaryDirectory(prefix="sharelint-freeze-") as temporary_name:
        frozen = _build_frozen_executable(target, Path(temporary_name))
        native_runtime = _read_native_runtime(frozen, target, build_root=Path(temporary_name))
        executable = output_dir / target.executable_name
        _write_bytes_exclusive(executable, frozen.read_bytes(), mode=0o755)

    root_name = f"sharelint-v{version}-{target.slug}"
    archive_path = output_dir / f"{root_name}{target.archive_suffix}"
    project_license = REPOSITORY_ROOT / "LICENSE"
    template = REPOSITORY_ROOT / "scripts" / "PORTABLE_README.txt"
    third_party_notices_path = REPOSITORY_ROOT / "scripts" / "THIRD-PARTY-NOTICES.txt"
    for required in (project_license, template, third_party_notices_path, LICENSE_CATALOG):
        if not required.is_file() or required.is_symlink():
            raise PortableBuildError(f"required release file is missing or unsafe: {required.name}")
    members = (
        ArchiveMember(f"{root_name}/{target.executable_name}", executable.read_bytes(), 0o755),
        ArchiveMember(
            f"{root_name}/BUILD-INFO.json",
            _build_info(
                executable.read_bytes(),
                target,
                version,
                native_runtime,
                third_party_notices_path.read_bytes(),
            ),
        ),
        ArchiveMember(
            f"{root_name}/README.txt",
            _render_portable_readme(template, version=version, target=target),
        ),
        ArchiveMember(f"{root_name}/LICENSE.txt", project_license.read_bytes()),
        ArchiveMember(f"{root_name}/PYTHON-LICENSE.txt", _find_python_license().read_bytes()),
        ArchiveMember(
            f"{root_name}/PYINSTALLER-LICENSE.txt", _find_pyinstaller_license().read_bytes()
        ),
        ArchiveMember(
            f"{root_name}/THIRD-PARTY-NOTICES.txt", third_party_notices_path.read_bytes()
        ),
    )
    if target.archive_suffix == ".zip":
        _write_zip(archive_path, root_name, members)
    else:
        _write_tar_gz(archive_path, root_name, members)

    digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    checksum_path = output_dir / f"{archive_path.name}.sha256"
    _write_bytes_exclusive(checksum_path, f"{digest}  {archive_path.name}\n".encode("ascii"))
    return executable, archive_path, checksum_path


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build the installed ShareLint wheel as one native portable release archive."
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("portable-build"),
        help="empty destination directory (default: portable-build)",
    )
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    try:
        executable, archive, checksum = build_portable(arguments.output_dir)
    except PortableBuildError as exc:
        print(f"portable build failed: {exc}", file=sys.stderr)
        if os.environ.get("GITHUB_ACTIONS") == "true":
            message = str(exc).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
            print(f"::error title=Portable build::{message}")
        return 2
    print(f"Executable: {executable}")
    print(f"Archive:    {archive}")
    print(f"Checksum:   {checksum}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
