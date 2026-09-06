#!/usr/bin/env python3
"""Verify portable archive bytes, metadata, inventory, and checksum contracts."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import stat
import struct
import sys
import tarfile
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import Path

if not __package__:  # Make the repository package importable during direct execution.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.build_portable import (  # noqa: E402
    LICENSE_CATALOG,
    MAX_NATIVE_FILE_BYTES,
    MAX_NATIVE_FILES,
    MAX_NATIVE_TOTAL_BYTES,
    NativeFileIdentity,
    NativeRuntimeInventory,
    PortableBuildError,
    PortableTarget,
    StaticComponentEvidence,
    _license_catalog,
    _read_native_runtime,
    _render_portable_readme,
    classify_native_runtime,
)

TARGETS = {
    "linux-glibc-x86_64": (".tar.gz", "sharelint"),
    "windows-x86_64": (".zip", "sharelint.exe"),
    "macos-x86_64": (".tar.gz", "sharelint"),
    "macos-arm64": (".tar.gz", "sharelint"),
}
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
BUILD_LOCKS = (
    REPOSITORY_ROOT / "requirements" / "release-build.txt",
    REPOSITORY_ROOT / "requirements" / "standalone-build.txt",
)
MAX_MEMBER_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_CONTENT_BYTES = 512 * 1024 * 1024
TEXT_MEMBER_LIMITS = {
    "BUILD-INFO.json": 256 * 1024,
    "LICENSE.txt": 256 * 1024,
    "PYINSTALLER-LICENSE.txt": 512 * 1024,
    "PYTHON-LICENSE.txt": 512 * 1024,
    "README.txt": 64 * 1024,
    "THIRD-PARTY-NOTICES.txt": 2 * 1024 * 1024,
}
SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
SAFE_VERSION = re.compile(r"\A[0-9A-Za-z][0-9A-Za-z.+_-]*\Z")
PORTABLE_PYTHON_VERSION = "3.13.15"


class AssetVerificationError(RuntimeError):
    """Raised when a portable release asset violates its public contract."""


@dataclass(frozen=True)
class VerifiedArchive:
    archive: Path
    checksum: Path
    executable_sha256: str


def _file_sha256(path: Path, *, maximum_bytes: int) -> str:
    if path.stat().st_size > maximum_bytes:
        raise AssetVerificationError(f"release file exceeds its size budget: {path.name}")
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            total += len(chunk)
            if total > maximum_bytes:
                raise AssetVerificationError(f"release file exceeds its size budget: {path.name}")
            digest.update(chunk)
    return digest.hexdigest()


def _build_lock_sha256() -> str:
    digest = hashlib.sha256()
    for lock in BUILD_LOCKS:
        if lock.is_symlink() or not lock.is_file():
            raise AssetVerificationError("a required build lock file is missing or unsafe")
        digest.update(lock.name.encode("ascii") + b"\0" + lock.read_bytes())
    return digest.hexdigest()


def _expected_members(root: str, executable: str) -> dict[str, int]:
    names = {
        f"{root}/BUILD-INFO.json": 0o644,
        f"{root}/LICENSE.txt": 0o644,
        f"{root}/PYINSTALLER-LICENSE.txt": 0o644,
        f"{root}/PYTHON-LICENSE.txt": 0o644,
        f"{root}/README.txt": 0o644,
        f"{root}/THIRD-PARTY-NOTICES.txt": 0o644,
        f"{root}/{executable}": 0o755,
    }
    return names


def _member_limit(name: str) -> int:
    return TEXT_MEMBER_LIMITS.get(name.rsplit("/", 1)[-1], MAX_MEMBER_BYTES)


def _validate_zip_layout(
    archive_path: Path, members: list[zipfile.ZipInfo], contents: dict[str, bytes]
) -> None:
    """Reject preambles, gaps, local extras, descriptors, and trailing ZIP bytes."""

    eocd_size = 22
    size = archive_path.stat().st_size
    if size < eocd_size:
        raise AssetVerificationError("portable ZIP is truncated")
    with archive_path.open("rb") as stream:
        stream.seek(size - eocd_size)
        eocd = struct.unpack("<4s4H2LH", stream.read(eocd_size))
        signature, disk, directory_disk, disk_count, total_count, cd_size, cd_offset, comment = eocd
        if (
            signature != b"PK\x05\x06"
            or disk != 0
            or directory_disk != 0
            or disk_count != len(members)
            or total_count != len(members)
            or comment != 0
            or cd_offset + cd_size != size - eocd_size
        ):
            raise AssetVerificationError("portable ZIP end record or trailing bytes are invalid")

        next_offset = 0
        for member in members:
            if member.header_offset != next_offset or member.flag_bits != 0:
                raise AssetVerificationError(f"portable ZIP layout is invalid: {member.filename}")
            stream.seek(member.header_offset)
            local = struct.unpack("<4s5H3L2H", stream.read(30))
            (
                local_signature,
                extract_version,
                flags,
                compression,
                modified_time,
                modified_date,
                crc,
                compressed_size,
                file_size,
                name_size,
                extra_size,
            ) = local
            encoded_name = member.filename.encode("ascii")
            if (
                local_signature != b"PK\x03\x04"
                or extract_version != 20
                or flags != 0
                or compression != zipfile.ZIP_DEFLATED
                or modified_time != 0
                or modified_date != 0x21
                or crc != member.CRC
                or compressed_size != member.compress_size
                or file_size != member.file_size
                or name_size != len(encoded_name)
                or extra_size != 0
                or stream.read(name_size) != encoded_name
            ):
                raise AssetVerificationError(
                    f"portable ZIP local header is invalid: {member.filename}"
                )
            compressed = stream.read(compressed_size)
            decoder = zlib.decompressobj(-zlib.MAX_WBITS)
            try:
                decoded = decoder.decompress(compressed, _member_limit(member.filename) + 1)
                if decoder.unconsumed_tail:
                    raise AssetVerificationError(
                        f"portable ZIP deflate budget was exceeded: {member.filename}"
                    )
                decoded += decoder.flush()
            except zlib.error as exc:
                raise AssetVerificationError(
                    f"portable ZIP deflate stream is invalid: {member.filename}"
                ) from exc
            if (
                not decoder.eof
                or decoder.unused_data
                or len(decoded) != member.file_size
                or decoded != contents[member.filename]
            ):
                raise AssetVerificationError(
                    f"portable ZIP deflate boundary is invalid: {member.filename}"
                )
            next_offset = stream.tell()
        if next_offset != cd_offset:
            raise AssetVerificationError("portable ZIP has hidden bytes before its directory")

        cursor = cd_offset
        for member in members:
            stream.seek(cursor)
            central = struct.unpack("<4s6H3L5H2L", stream.read(46))
            (
                central_signature,
                created_by,
                extract_version,
                flags,
                compression,
                modified_time,
                modified_date,
                crc,
                compressed_size,
                file_size,
                name_size,
                extra_size,
                comment_size,
                member_disk,
                internal_attributes,
                external_attributes,
                local_offset,
            ) = central
            encoded_name = member.filename.encode("ascii")
            if (
                central_signature != b"PK\x01\x02"
                or created_by != 0x0314
                or extract_version != 20
                or flags != 0
                or compression != zipfile.ZIP_DEFLATED
                or modified_time != 0
                or modified_date != 0x21
                or crc != member.CRC
                or compressed_size != member.compress_size
                or file_size != member.file_size
                or name_size != len(encoded_name)
                or extra_size != 0
                or comment_size != 0
                or member_disk != 0
                or internal_attributes != 0
                or external_attributes != member.external_attr
                or local_offset != member.header_offset
                or stream.read(name_size) != encoded_name
            ):
                raise AssetVerificationError(
                    f"portable ZIP central directory is invalid: {member.filename}"
                )
            cursor = stream.tell()
        if cursor != cd_offset + cd_size:
            raise AssetVerificationError("portable ZIP central directory has hidden bytes")


def _canonical_tar_bytes(contents: dict[str, bytes], expected: dict[str, int]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name in sorted(expected):
            info = tarfile.TarInfo(name)
            info.size = len(contents[name])
            info.mode = expected[name]
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            archive.addfile(info, io.BytesIO(contents[name]))
    return output.getvalue()


def _read_bounded_gzip_payload(archive_path: Path, *, maximum_bytes: int) -> bytes:
    """Return one fixed-header gzip payload without accepting concatenated data."""

    raw = archive_path.read_bytes()
    if not raw.startswith(b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff"):
        raise AssetVerificationError("portable gzip header is not canonical")
    decoder = zlib.decompressobj(zlib.MAX_WBITS | 16)
    try:
        unpacked = decoder.decompress(raw, maximum_bytes + 1)
        if decoder.unconsumed_tail:
            raise AssetVerificationError("portable gzip content budget was exceeded")
        unpacked += decoder.flush()
    except zlib.error as exc:
        raise AssetVerificationError("portable gzip stream is invalid") from exc
    if not decoder.eof or decoder.unused_data or len(unpacked) > maximum_bytes:
        raise AssetVerificationError("portable gzip has invalid or hidden trailing data")
    return unpacked


def _recorded_native_runtime(value: object, target: str) -> NativeRuntimeInventory:
    expected_keys = {
        "analysis_inventory_sha256",
        "components",
        "files",
        "package_inventory_sha256",
        "static_components",
    }
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise AssetVerificationError("BUILD-INFO.json native runtime inventory is invalid")

    raw_files = value.get("files")
    if not isinstance(raw_files, list) or not raw_files or len(raw_files) > MAX_NATIVE_FILES:
        raise AssetVerificationError("BUILD-INFO.json native file inventory is malformed")
    identities: list[NativeFileIdentity] = []
    total = 0
    for record in raw_files:
        if not isinstance(record, dict) or set(record) != {"name", "sha256", "size", "typecode"}:
            raise AssetVerificationError("BUILD-INFO.json native file identity is malformed")
        name = record.get("name")
        digest = record.get("sha256")
        size = record.get("size")
        typecode = record.get("typecode")
        if (
            not isinstance(name, str)
            or not isinstance(digest, str)
            or not SHA256.fullmatch(digest)
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size <= 0
            or size > MAX_NATIVE_FILE_BYTES
            or typecode != "b"
        ):
            raise AssetVerificationError("BUILD-INFO.json native file identity is invalid")
        total += size
        if total > MAX_NATIVE_TOTAL_BYTES:
            raise AssetVerificationError("BUILD-INFO.json native file inventory exceeds its budget")
        identities.append(
            NativeFileIdentity(name=name, sha256=digest, size=size, typecode=typecode)
        )
    if identities != sorted(identities, key=lambda item: item.name) or len(
        {item.name for item in identities}
    ) != len(identities):
        raise AssetVerificationError("BUILD-INFO.json native file identities are not canonical")

    raw_static = value.get("static_components")
    if not isinstance(raw_static, list) or len(raw_static) > MAX_NATIVE_FILES:
        raise AssetVerificationError("BUILD-INFO.json static component inventory is malformed")
    static_components: list[StaticComponentEvidence] = []
    for record in raw_static:
        if (
            not isinstance(record, dict)
            or set(record) != {"component", "match", "origin", "version"}
            or not all(isinstance(record[key], str) and record[key] for key in record)
        ):
            raise AssetVerificationError("BUILD-INFO.json static component evidence is invalid")
        static_components.append(
            StaticComponentEvidence(
                component=record["component"],
                match=record["match"],
                origin=record["origin"],
                version=record["version"],
            )
        )
    canonical_static = sorted(
        set(static_components),
        key=lambda item: (item.component, item.version, item.origin, item.match),
    )
    if static_components != canonical_static:
        raise AssetVerificationError("BUILD-INFO.json static component evidence is not canonical")

    names = tuple(item.name for item in identities)
    try:
        classified = classify_native_runtime(names, target)
    except PortableBuildError as exc:
        raise AssetVerificationError(
            "BUILD-INFO.json has an unreviewed native runtime file"
        ) from exc
    raw_components = value.get("components")
    if (
        not isinstance(raw_components, list)
        or raw_components != list(classified.components)
        or tuple(static_components) != classified.static_components
    ):
        raise AssetVerificationError("BUILD-INFO.json native component mapping is invalid")
    analysis_digest = value.get("analysis_inventory_sha256")
    package_digest = value.get("package_inventory_sha256")
    if (
        not isinstance(analysis_digest, str)
        or not SHA256.fullmatch(analysis_digest)
        or not isinstance(package_digest, str)
        or not SHA256.fullmatch(package_digest)
        or analysis_digest != package_digest
    ):
        raise AssetVerificationError("BUILD-INFO.json build-stage inventory binding is invalid")
    return NativeRuntimeInventory(
        files=names,
        components=classified.components,
        identities=tuple(identities),
        static_components=tuple(static_components),
        analysis_inventory_sha256=analysis_digest,
        package_inventory_sha256=package_digest,
    )


def _validate_contents(
    contents: dict[str, bytes], *, root: str, executable: str, target: str, version: str
) -> tuple[str, NativeRuntimeInventory]:
    executable_bytes = contents[f"{root}/{executable}"]
    executable_digest = hashlib.sha256(executable_bytes).hexdigest()
    if not executable_bytes:
        raise AssetVerificationError("portable executable is empty")
    try:
        build_info = json.loads(contents[f"{root}/BUILD-INFO.json"])
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AssetVerificationError("BUILD-INFO.json is not valid UTF-8 JSON") from exc
    expected_build_info_keys = {
        "build_components",
        "build_lock_sha256",
        "executable_sha256",
        "format_version",
        "license_catalog_sha256",
        "native_runtime",
        "python",
        "sharelint_version",
        "target",
        "third_party_notices_sha256",
    }
    if not isinstance(build_info, dict) or set(build_info) != expected_build_info_keys:
        raise AssetVerificationError("BUILD-INFO.json root must be an object")
    if (
        build_info.get("format_version") != 2
        or build_info.get("target") != target
        or build_info.get("sharelint_version") != version
        or build_info.get("executable_sha256") != executable_digest
        or build_info.get("build_lock_sha256") != _build_lock_sha256()
    ):
        raise AssetVerificationError("BUILD-INFO.json byte binding or target metadata is invalid")
    native_runtime = _recorded_native_runtime(build_info.get("native_runtime"), target)
    components = build_info.get("build_components")
    expected_components = {
        "altgraph": "0.17.5",
        "build": "1.5.0",
        "packaging": "26.3",
        "pip": "26.2.1",
        "pyinstaller": "6.22.2",
        "pyinstaller-hooks-contrib": "2026.6",
        "pyproject-hooks": "1.2.0",
        "setuptools": "84.0.0",
        "sharelint": version,
    }
    if target.startswith("macos-"):
        expected_components["macholib"] = "1.16.4"
    if target.startswith("windows-"):
        expected_components.update(
            {"colorama": "0.4.6", "pefile": "2024.8.26", "pywin32-ctypes": "0.2.3"}
        )
    if not isinstance(components, dict) or components != expected_components:
        raise AssetVerificationError("BUILD-INFO.json component inventory is incomplete")
    python = build_info.get("python")
    if (
        not isinstance(python, dict)
        or python.get("implementation") != "CPython"
        or python.get("version") != PORTABLE_PYTHON_VERSION
    ):
        raise AssetVerificationError("BUILD-INFO.json Python identity is invalid")
    project_license = REPOSITORY_ROOT / "LICENSE"
    if project_license.is_symlink() or not project_license.is_file():
        raise AssetVerificationError("repository license is missing or unsafe")
    if contents[f"{root}/LICENSE.txt"] != project_license.read_bytes():
        raise AssetVerificationError("portable archive project license is invalid")
    if (
        b"PYTHON SOFTWARE FOUNDATION LICENSE VERSION 2"
        not in contents[f"{root}/PYTHON-LICENSE.txt"].upper()
    ):
        raise AssetVerificationError("portable archive lacks the embedded CPython license")
    if b"Bootloader Exception" not in contents[f"{root}/PYINSTALLER-LICENSE.txt"]:
        raise AssetVerificationError("portable archive lacks the PyInstaller bootloader exception")
    try:
        catalog = _license_catalog()
    except PortableBuildError as exc:
        raise AssetVerificationError("repository native license catalog is invalid") from exc
    if (
        build_info.get("license_catalog_sha256")
        != hashlib.sha256(LICENSE_CATALOG.read_bytes()).hexdigest()
    ):
        raise AssetVerificationError("BUILD-INFO.json native license catalog binding is invalid")
    notices_path = REPOSITORY_ROOT / "scripts" / "THIRD-PARTY-NOTICES.txt"
    if notices_path.is_symlink() or not notices_path.is_file():
        raise AssetVerificationError("repository third-party notices are missing or unsafe")
    notices = contents[f"{root}/THIRD-PARTY-NOTICES.txt"]
    if notices != notices_path.read_bytes():
        raise AssetVerificationError("portable archive third-party notices are invalid")
    if build_info.get("third_party_notices_sha256") != hashlib.sha256(notices).hexdigest():
        raise AssetVerificationError("BUILD-INFO.json third-party notice binding is invalid")
    component_catalog = catalog.get("components")
    if not isinstance(component_catalog, dict):
        raise AssetVerificationError("repository native license component map is invalid")
    for component in native_runtime.components:
        record = component_catalog.get(component)
        if not isinstance(record, dict) or not isinstance(record.get("sources"), list):
            raise AssetVerificationError("portable native component lacks a notice catalog entry")
        for source in record["sources"]:
            if (
                not isinstance(source, dict)
                or not isinstance(source.get("notice_marker"), str)
                or source["notice_marker"].encode("utf-8") not in notices
            ):
                raise AssetVerificationError(
                    "portable notices do not cover the frozen native components"
                )
    suffix, expected_executable = TARGETS[target]
    rendered_readme = _render_portable_readme(
        REPOSITORY_ROOT / "scripts" / "PORTABLE_README.txt",
        version=version,
        target=PortableTarget(target, expected_executable, suffix),
    )
    if contents[f"{root}/README.txt"] != rendered_readme:
        raise AssetVerificationError("portable archive README is invalid")
    return executable_digest, native_runtime


def _read_zip(archive_path: Path, expected: dict[str, int]) -> dict[str, bytes]:
    contents: dict[str, bytes] = {}
    with zipfile.ZipFile(archive_path) as archive:
        if archive.comment:
            raise AssetVerificationError("portable ZIP has an archive comment")
        members = archive.infolist()
        if len(members) != len(expected) or [item.filename for item in members] != sorted(expected):
            raise AssetVerificationError("portable ZIP member set is invalid")
        total = 0
        for member in members:
            expected_mode = expected[member.filename]
            unix_mode = (member.external_attr >> 16) & 0o177777
            if (
                member.create_system != 3
                or unix_mode != stat.S_IFREG | expected_mode
                or member.comment
                or member.extra
                or member.flag_bits & 0x1
                or member.compress_type != zipfile.ZIP_DEFLATED
                or member.date_time != (1980, 1, 1, 0, 0, 0)
                or member.file_size > _member_limit(member.filename)
                or member.compress_size > _member_limit(member.filename)
            ):
                raise AssetVerificationError(f"portable ZIP metadata is invalid: {member.filename}")
            total += member.file_size
            if total > MAX_ARCHIVE_CONTENT_BYTES:
                raise AssetVerificationError("portable ZIP content budget was exceeded")
            contents[member.filename] = archive.read(member)
    _validate_zip_layout(archive_path, members, contents)
    return contents


def _read_tar(archive_path: Path, expected: dict[str, int]) -> dict[str, bytes]:
    contents: dict[str, bytes] = {}
    maximum_tar_bytes = MAX_ARCHIVE_CONTENT_BYTES + len(expected) * 1024 + tarfile.RECORDSIZE
    unpacked = _read_bounded_gzip_payload(archive_path, maximum_bytes=maximum_tar_bytes)
    with tarfile.open(fileobj=io.BytesIO(unpacked), mode="r:") as archive:
        if archive.pax_headers:
            raise AssetVerificationError("portable TAR has unexpected global PAX metadata")
        members = archive.getmembers()
        if len(members) != len(expected) or {item.name for item in members} != set(expected):
            raise AssetVerificationError("portable TAR member set is invalid")
        total = 0
        for member in members:
            if (
                not member.isreg()
                or member.mode != expected[member.name]
                or member.mtime != 0
                or member.uid != 0
                or member.gid != 0
                or member.uname
                or member.gname
                or member.pax_headers
                or member.size > _member_limit(member.name)
            ):
                raise AssetVerificationError(f"portable TAR metadata is invalid: {member.name}")
            total += member.size
            if total > MAX_ARCHIVE_CONTENT_BYTES:
                raise AssetVerificationError("portable TAR content budget was exceeded")
            stream = archive.extractfile(member)
            if stream is None:
                raise AssetVerificationError(f"portable TAR member is unreadable: {member.name}")
            contents[member.name] = stream.read(_member_limit(member.name) + 1)
            if len(contents[member.name]) != member.size:
                raise AssetVerificationError(
                    f"portable TAR member size is inconsistent: {member.name}"
                )
    if unpacked != _canonical_tar_bytes(contents, expected):
        raise AssetVerificationError(
            "portable tar.gz has non-canonical USTAR data or hidden tar bytes"
        )
    return contents


def verify_archive(
    archive_path: Path,
    checksum_path: Path,
    *,
    target: str,
    version: str,
    loose_executable: Path | None = None,
) -> VerifiedArchive:
    if target not in TARGETS:
        raise AssetVerificationError(f"unknown portable target: {target}")
    suffix, executable = TARGETS[target]
    root = f"sharelint-v{version}-{target}"
    expected_archive = f"{root}{suffix}"
    if archive_path.name != expected_archive or checksum_path.name != f"{expected_archive}.sha256":
        raise AssetVerificationError("portable asset filename is invalid")
    for path in (archive_path, checksum_path):
        if path.is_symlink() or not path.is_file():
            raise AssetVerificationError("portable assets must be regular non-symlink files")
    archive_digest = _file_sha256(archive_path, maximum_bytes=MAX_ARCHIVE_CONTENT_BYTES)
    if checksum_path.stat().st_size > 256:
        raise AssetVerificationError("portable checksum file exceeds its size budget")
    try:
        checksum = checksum_path.read_text(encoding="ascii")
    except (OSError, UnicodeDecodeError) as exc:
        raise AssetVerificationError("portable checksum is not readable ASCII") from exc
    if checksum != f"{archive_digest}  {expected_archive}\n":
        raise AssetVerificationError("portable checksum line is invalid")
    expected = _expected_members(root, executable)
    try:
        contents = (
            _read_zip(archive_path, expected)
            if suffix == ".zip"
            else _read_tar(archive_path, expected)
        )
    except (OSError, struct.error, tarfile.TarError, zipfile.BadZipFile, RuntimeError) as exc:
        if isinstance(exc, AssetVerificationError):
            raise
        raise AssetVerificationError("portable archive could not be parsed safely") from exc
    executable_digest, recorded_native_runtime = _validate_contents(
        contents, root=root, executable=executable, target=target, version=version
    )
    if loose_executable is not None:
        if loose_executable.is_symlink() or not loose_executable.is_file():
            raise AssetVerificationError("loose executable must be a regular non-symlink file")
        if _file_sha256(loose_executable, maximum_bytes=MAX_MEMBER_BYTES) != executable_digest:
            raise AssetVerificationError("archived executable differs from the smoke-tested bytes")
        try:
            actual_native_runtime = _read_native_runtime(
                loose_executable, PortableTarget(target, executable, suffix)
            )
        except PortableBuildError as exc:
            raise AssetVerificationError(
                "loose executable native inventory is not verifiable"
            ) from exc
        if (
            actual_native_runtime.files != recorded_native_runtime.files
            or actual_native_runtime.components != recorded_native_runtime.components
            or actual_native_runtime.identities != recorded_native_runtime.identities
            or actual_native_runtime.static_components != recorded_native_runtime.static_components
            or actual_native_runtime.analysis_inventory_sha256
            or actual_native_runtime.package_inventory_sha256
        ):
            raise AssetVerificationError(
                "loose executable native inventory differs from BUILD-INFO.json"
            )
    return VerifiedArchive(archive_path, checksum_path, executable_digest)


def verify_directory(
    directory: Path,
    *,
    version: str,
    target: str | None,
    all_targets: bool,
    loose_executable: Path | None,
) -> tuple[VerifiedArchive, ...]:
    if directory.is_symlink() or not directory.is_dir():
        raise AssetVerificationError("release asset directory must be a real directory")
    if not SAFE_VERSION.fullmatch(version):
        raise AssetVerificationError("portable release version is unsafe")
    if not all_targets and target not in TARGETS:
        raise AssetVerificationError("one known --target is required")
    targets = tuple(TARGETS) if all_targets else (str(target),)
    expected_files: set[str] = set()
    verified = []
    for item in targets:
        suffix, _ = TARGETS[item]
        archive_name = f"sharelint-v{version}-{item}{suffix}"
        checksum_name = f"{archive_name}.sha256"
        expected_files.update((archive_name, checksum_name))
        verified.append(
            verify_archive(
                directory / archive_name,
                directory / checksum_name,
                target=item,
                version=version,
                loose_executable=loose_executable if not all_targets else None,
            )
        )
    permitted_extra: set[str] = set()
    if loose_executable is not None:
        try:
            if loose_executable.parent.resolve() == directory.resolve():
                permitted_extra.add(loose_executable.name)
        except OSError as exc:
            raise AssetVerificationError("loose executable path is not inspectable") from exc
    actual_entries = {path.name for path in directory.iterdir()}
    if actual_entries != expected_files | permitted_extra:
        raise AssetVerificationError("portable release asset set is incomplete or has extra files")
    return tuple(verified)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Verify ShareLint portable release archives.")
    parser.add_argument("directory", type=Path)
    parser.add_argument("--version", required=True)
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("--target", choices=tuple(TARGETS))
    target_group.add_argument("--all-targets", action="store_true")
    parser.add_argument("--executable", type=Path, help="loose executable already smoke-tested")
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    if arguments.all_targets and arguments.executable is not None:
        print("asset verification failed: --executable requires one --target", file=sys.stderr)
        return 2
    try:
        verified = verify_directory(
            arguments.directory,
            version=arguments.version,
            target=arguments.target,
            all_targets=arguments.all_targets,
            loose_executable=arguments.executable,
        )
    except AssetVerificationError as exc:
        print(f"asset verification failed: {exc}", file=sys.stderr)
        return 1
    for item in verified:
        print(f"Verified {item.archive.name} · executable sha256:{item.executable_sha256}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
