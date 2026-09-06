#!/usr/bin/env python3
"""Normalize one setuptools sdist to reproducible, bounded tar.gz bytes."""

from __future__ import annotations

import argparse
import gzip
import io
import os
import re
import sys
import tarfile
import tempfile
import zlib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

MAX_COMPRESSED_BYTES = 64 * 1024 * 1024
MAX_MEMBER_BYTES = 16 * 1024 * 1024
MAX_CONTENT_BYTES = 128 * 1024 * 1024
MAX_MEMBERS = 4096
MAX_TAR_BYTES = MAX_CONTENT_BYTES + MAX_MEMBERS * 1024 + tarfile.RECORDSIZE
SAFE_PROJECT = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]*\Z")
SAFE_VERSION = re.compile(r"\A[0-9A-Za-z][0-9A-Za-z.+_-]*\Z")


class SdistNormalizationError(RuntimeError):
    """Raised when an sdist is unsafe, ambiguous, or not canonical."""


@dataclass(frozen=True)
class SdistMember:
    name: str
    data: bytes | None
    executable: bool = False


def _expected_base(project: str, version: str) -> str:
    if not SAFE_PROJECT.fullmatch(project) or not SAFE_VERSION.fullmatch(version):
        raise SdistNormalizationError("project or version is unsafe for an sdist name")
    normalized_project = re.sub(r"[-_.]+", "-", project).lower()
    return f"{normalized_project}-{version}"


def _bounded_gzip_payload(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise SdistNormalizationError("sdist must be a regular non-symlink file")
    if path.stat().st_size > MAX_COMPRESSED_BYTES:
        raise SdistNormalizationError("sdist exceeds its compressed size budget")
    raw = path.read_bytes()
    decoder = zlib.decompressobj(zlib.MAX_WBITS | 16)
    try:
        payload = decoder.decompress(raw, MAX_TAR_BYTES + 1)
        if decoder.unconsumed_tail:
            raise SdistNormalizationError("sdist exceeds its expanded size budget")
        payload += decoder.flush()
    except zlib.error as exc:
        raise SdistNormalizationError("sdist gzip stream is invalid") from exc
    if not decoder.eof or decoder.unused_data or len(payload) > MAX_TAR_BYTES:
        raise SdistNormalizationError("sdist gzip stream has hidden or excessive data")
    return payload


def _read_members(path: Path, *, root: str) -> tuple[SdistMember, ...]:
    payload = _bounded_gzip_payload(path)
    collected: list[SdistMember] = []
    names: set[str] = set()
    total = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as archive:
            if archive.pax_headers:
                raise SdistNormalizationError("sdist has unexpected global PAX metadata")
            for count, member in enumerate(archive, start=1):
                if count > MAX_MEMBERS:
                    raise SdistNormalizationError("sdist exceeds its member-count budget")
                pure = PurePosixPath(member.name)
                if (
                    not member.name
                    or pure.is_absolute()
                    or "\\" in member.name
                    or ".." in pure.parts
                    or pure.parts[0] != root
                    or member.name in names
                ):
                    raise SdistNormalizationError(f"sdist has an unsafe member: {member.name!r}")
                names.add(member.name)
                if member.isdir():
                    if member.size != 0:
                        raise SdistNormalizationError("sdist directory has a non-zero size")
                    collected.append(SdistMember(member.name, None))
                    continue
                if not member.isreg() or member.size > MAX_MEMBER_BYTES:
                    raise SdistNormalizationError(
                        f"sdist member is not a bounded regular file: {member.name!r}"
                    )
                total += member.size
                if total > MAX_CONTENT_BYTES:
                    raise SdistNormalizationError("sdist exceeds its total content budget")
                stream = archive.extractfile(member)
                if stream is None:
                    raise SdistNormalizationError(f"sdist member is unreadable: {member.name!r}")
                data = stream.read(MAX_MEMBER_BYTES + 1)
                if len(data) != member.size:
                    raise SdistNormalizationError(
                        f"sdist member size is inconsistent: {member.name!r}"
                    )
                collected.append(SdistMember(member.name, data, bool(member.mode & 0o111)))
            if (
                len(payload) % tarfile.RECORDSIZE != 0
                or len(payload) - archive.offset < 1024
                or any(payload[archive.offset :])
            ):
                raise SdistNormalizationError("sdist tar stream has hidden trailing data")
    except tarfile.TarError as exc:
        raise SdistNormalizationError("sdist tar stream is invalid") from exc
    if root not in names or not any(
        member.name == root and member.data is None for member in collected
    ):
        raise SdistNormalizationError("sdist lacks its required root directory")
    return tuple(sorted(collected, key=lambda item: item.name))


def _canonical_bytes(members: tuple[SdistMember, ...]) -> bytes:
    raw = io.BytesIO()
    with (
        gzip.GzipFile(filename="", mode="wb", fileobj=raw, compresslevel=9, mtime=0) as zipped,
        tarfile.open(fileobj=zipped, mode="w", format=tarfile.USTAR_FORMAT) as archive,
    ):
        for member in members:
            info = tarfile.TarInfo(member.name)
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            if member.data is None:
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                info.size = 0
                archive.addfile(info)
            else:
                info.mode = 0o755 if member.executable else 0o644
                info.size = len(member.data)
                archive.addfile(info, io.BytesIO(member.data))
    return raw.getvalue()


def canonical_sdist_bytes(path: Path, *, project: str, version: str) -> bytes:
    """Return canonical bytes after strict validation of an existing sdist."""

    root = _expected_base(project, version)
    if path.name != f"{root}.tar.gz":
        raise SdistNormalizationError("sdist filename does not match the project and version")
    return _canonical_bytes(_read_members(path, root=root))


def normalize_sdist(path: Path, *, project: str, version: str, check: bool = False) -> None:
    """Atomically normalize an sdist, or only check that it is already canonical."""

    canonical = canonical_sdist_bytes(path, project=project, version=version)
    if check:
        if path.read_bytes() != canonical:
            raise SdistNormalizationError("sdist is valid but not canonical")
        return
    if path.read_bytes() == canonical:
        return
    with tempfile.NamedTemporaryFile(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent, delete=False
    ) as stream:
        temporary = Path(stream.name)
        stream.write(canonical)
        stream.flush()
        os.fsync(stream.fileno())
    try:
        if os.name == "posix":
            temporary.chmod(0o644)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Create or verify one canonical Python sdist.")
    parser.add_argument("sdist", type=Path)
    parser.add_argument("--project", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--check", action="store_true")
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    try:
        normalize_sdist(
            arguments.sdist,
            project=arguments.project,
            version=arguments.version,
            check=arguments.check,
        )
    except (OSError, SdistNormalizationError) as exc:
        print(f"sdist normalization failed: {exc}", file=sys.stderr)
        return 1
    action = "Verified" if arguments.check else "Normalized"
    print(f"{action} canonical sdist: {arguments.sdist.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
