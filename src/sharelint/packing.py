"""Fail-closed deterministic ZIP creation and hash-bound receipts."""

from __future__ import annotations

import hashlib
import io
import json
import lzma
import os
import stat
import tempfile
import zipfile
import zlib
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import IO, Any

from .extended_attributes import ExtendedAttributeStatus, probe_extended_attributes
from .filesystem import bounded_directory_items, metadata_matches_open_file
from .models import ScanLimits, ScanReport, Severity
from .reporters import canonical_json, render_json
from .rules import RULES
from .scanner import ScanInputError, scan
from .scanners.archive import has_excessive_central_directory, normalized_member_name
from .windows_streams import WindowsStreamStatus, inspect_windows_streams


class PackError(RuntimeError):
    """Base class for expected pack failures."""


class PackBlocked(PackError):
    def __init__(
        self,
        report: ScanReport,
        reasons: list[str],
        *,
        receipt: Path | None = None,
        report_output: Path | None = None,
    ) -> None:
        super().__init__("share bundle did not satisfy the pack policy")
        self.report = report
        self.reasons = reasons
        self.receipt = receipt
        self.report_output = report_output


@dataclass(frozen=True, slots=True)
class PackedArtifact:
    output: Path
    receipt: Path | None
    report_output: Path | None
    report: ScanReport
    archive_sha256: str
    archive_size: int
    files: tuple[dict[str, Any], ...]


@dataclass(frozen=True, slots=True)
class _PublishedFile:
    """A published inode kept alive by a private hard-link anchor."""

    anchor: Path
    device: int
    inode: int
    size: int
    sha256: str


@dataclass(frozen=True, slots=True)
class _SourceWriteResult:
    """Files written plus the exact source snapshot observed while writing them."""

    files: list[dict[str, Any]]
    target_kind: str
    target_sha256: str


def _zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | 0o644) << 16
    info.flag_bits |= 0x800
    return info


def _read_bounded(stream: IO[bytes], limit: int) -> bytes:
    if limit < 0:
        raise PackError("negative pack read limit")
    result = bytearray()
    while len(result) <= limit:
        chunk = stream.read(min(64 * 1024, limit + 1 - len(result)))
        if not chunk:
            break
        result.extend(chunk)
    if len(result) > limit:
        raise PackError("an input grew beyond the configured pack limit")
    return bytes(result)


def _read_regular(path: Path, limit: int) -> bytes:
    try:
        before = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise PackError("an input file could not be inspected for packing") from exc
    if not stat.S_ISREG(before.st_mode):
        raise PackError("pack accepts regular files only")
    if before.st_size > limit:
        raise PackError("an input file exceeds the configured pack limit")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise PackError("an input file could not be opened safely for packing") from exc
    try:
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if not metadata_matches_open_file(before, opened):
                raise PackError("an input file changed before it could be packed")
            data = _read_bounded(stream, limit)
            after = os.fstat(stream.fileno())
    except OSError as exc:
        raise PackError("an input file could not be read for packing") from exc
    if (after.st_size, after.st_mtime_ns) != (opened.st_size, opened.st_mtime_ns):
        raise PackError("an input file changed while it was being packed")
    return data


def _write_entry(
    archive: zipfile.ZipFile,
    name: str,
    data: bytes,
    files: list[dict[str, Any]],
) -> None:
    archive.writestr(_zip_info(name), data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    files.append({"path": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})


def _directory_candidates(root: Path, limit: int) -> list[Path]:
    candidates, errors, limited = bounded_directory_items(root, limit)
    if errors:
        raise PackError("source directory could not be enumerated completely")
    if limited:
        raise PackError("source contains more entries than the configured pack limit")
    return candidates


def _validate_zip_info(
    info: zipfile.ZipInfo,
    names_seen: set[str],
    limits: ScanLimits,
) -> str | None:
    normalized = normalized_member_name(info.filename)
    mode = (info.external_attr >> 16) & 0xFFFF
    if normalized is None:
        raise PackError("archive changed after scan or contains an unsafe member path")
    if normalized in names_seen:
        raise PackError("archive changed after scan or contains duplicate member paths")
    names_seen.add(normalized)
    if stat.S_IFMT(mode) == stat.S_IFLNK:
        raise PackError("archive changed after scan or contains a symbolic link")
    if info.flag_bits & 0x1:
        raise PackError("archive changed after scan or contains an encrypted member")
    if info.is_dir():
        return None
    ratio = (
        float("inf")
        if info.compress_size == 0 and info.file_size > 0
        else info.file_size / max(1, info.compress_size)
    )
    if info.file_size > limits.max_member_bytes or ratio > limits.max_compression_ratio:
        raise PackError("archive member exceeds a configured pack safety limit")
    return normalized


def _read_zip_member(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    limits: ScanLimits,
    remaining: int,
) -> bytes:
    limit = min(limits.max_member_bytes, remaining)
    if info.file_size > limit:
        raise PackError("archive members exceed the total pack byte budget")
    try:
        with archive.open(info, "r") as stream:
            data = _read_bounded(stream, limit)
    except (
        EOFError,
        RuntimeError,
        ValueError,
        zipfile.BadZipFile,
        lzma.LZMAError,
        OSError,
        NotImplementedError,
        zlib.error,
    ) as exc:
        raise PackError("an archive member could not be read safely") from exc
    if len(data) != info.file_size:
        raise PackError("an archive member did not match its directory record")
    return data


def _write_source(
    archive: zipfile.ZipFile,
    source: Path,
    limits: ScanLimits,
) -> _SourceWriteResult:
    files: list[dict[str, Any]] = []
    total = 0
    if source.is_dir():
        manifest = hashlib.sha256()
        candidates = _directory_candidates(source, limits.max_archive_members)
        if len(candidates) > limits.max_archive_members:
            raise PackError("source contains more entries than the configured pack limit")
        for item in candidates:
            relative = item.relative_to(source).as_posix()
            if normalized_member_name(relative) != relative:
                raise PackError("source contains a path that cannot be represented safely")
            data = _read_regular(item, min(limits.max_member_bytes, limits.max_total_bytes - total))
            total += len(data)
            manifest.update(os.fsencode(relative))
            manifest.update(b"\0")
            manifest.update(len(data).to_bytes(8, "big"))
            manifest.update(hashlib.sha256(data).digest())
            _write_entry(archive, relative, data, files)
        return _SourceWriteResult(files, "directory", manifest.hexdigest())

    source_data = _read_regular(source, limits.max_file_bytes)
    source_sha256 = hashlib.sha256(source_data).hexdigest()
    if source_data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        if has_excessive_central_directory(source_data, limits.max_archive_members):
            raise PackError("archive contains more members than the configured pack limit")
        try:
            with zipfile.ZipFile(io.BytesIO(source_data)) as original:
                infos = original.infolist()
                if len(infos) > limits.max_archive_members:
                    raise PackError("archive contains more members than the configured pack limit")
                names_seen: set[str] = set()
                for info in sorted(infos, key=lambda item: item.filename):
                    normalized = _validate_zip_info(info, names_seen, limits)
                    if normalized is None:
                        continue
                    data = _read_zip_member(original, info, limits, limits.max_total_bytes - total)
                    total += len(data)
                    _write_entry(archive, normalized, data, files)
        except zipfile.BadZipFile as exc:
            raise PackError("input ZIP could not be reopened for packing") from exc
        return _SourceWriteResult(files, "file", source_sha256)

    if len(source_data) > limits.max_member_bytes:
        raise PackError("input file exceeds the archive-member safety limit")
    if normalized_member_name(source.name) != source.name:
        raise PackError("input filename cannot be represented safely in a ZIP archive")
    _write_entry(archive, source.name, source_data, files)
    return _SourceWriteResult(files, "file", source_sha256)


def _sha256_file(path: Path, limit: int) -> tuple[str, int]:
    try:
        size = path.stat(follow_symlinks=False).st_size
    except OSError as exc:
        raise PackError("completed archive could not be inspected") from exc
    if size > limit:
        raise PackError("completed archive exceeds the top-level scan limit")
    digest = hashlib.sha256()
    consumed = 0
    try:
        with path.open("rb") as stream:
            while chunk := stream.read(64 * 1024):
                consumed += len(chunk)
                if consumed > limit:
                    raise PackError("completed archive grew beyond the top-level scan limit")
                digest.update(chunk)
    except OSError as exc:
        raise PackError("completed archive could not be read") from exc
    if consumed != size:
        raise PackError("completed archive changed while it was being hashed")
    return digest.hexdigest(), consumed


def _manifest_from_zip(path: Path, limits: ScanLimits) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    total = 0
    names_seen: set[str] = set()
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            if len(infos) > limits.max_archive_members:
                raise PackError("completed archive exceeds the member-count limit")
            names = [item.filename for item in infos if not item.is_dir()]
            if names != sorted(names):
                raise PackError("completed archive entry order is not deterministic")
            for info in infos:
                normalized = _validate_zip_info(info, names_seen, limits)
                if normalized is None:
                    continue
                data = _read_zip_member(archive, info, limits, limits.max_total_bytes - total)
                total += len(data)
                result.append(
                    {
                        "path": normalized,
                        "size": len(data),
                        "sha256": hashlib.sha256(data).hexdigest(),
                    }
                )
    except zipfile.BadZipFile as exc:
        raise PackError("completed archive could not be reopened") from exc
    return result


def _ruleset_sha256() -> str:
    descriptor = {
        "format": "sharelint-ruleset-v1",
        "engine": "builtin-v1",
        "rules": [
            {
                "id": rule.rule_id,
                "title": rule.title,
                "severity": rule.severity.value,
                "remediation": rule.remediation,
                "tags": sorted(rule.tags),
            }
            for rule in (RULES[rule_id] for rule_id in sorted(RULES))
        ],
    }
    return hashlib.sha256(canonical_json(descriptor).encode("utf-8")).hexdigest()


def _policy_document(report: ScanReport, threshold: Severity) -> dict[str, Any]:
    ruleset_sha256 = _ruleset_sha256()
    descriptor = {
        "format": "sharelint-pack-policy-v1",
        "fail_on": threshold.value,
        "require_complete_coverage": True,
        "limits": report.limits.to_dict(),
        "ruleset_sha256": ruleset_sha256,
    }
    return {
        "sha256": hashlib.sha256(canonical_json(descriptor).encode("utf-8")).hexdigest(),
        "ruleset_sha256": ruleset_sha256,
        "fail_on": threshold.value,
        "require_complete_coverage": True,
        "limits": report.limits.to_dict(),
    }


def _report_bytes(report: ScanReport, threshold: Severity) -> bytes:
    return render_json(report, threshold).encode("utf-8")


def _report_sha256(exact_bytes: bytes) -> str:
    return hashlib.sha256(exact_bytes).hexdigest()


def _source_identity(report: ScanReport) -> dict[str, Any]:
    if report.has_coverage_gaps:
        return {"kind": report.target_kind, "hash_status": "unavailable"}
    return {
        "kind": report.target_kind,
        "hash_status": "complete",
        "sha256": report.target_sha256,
    }


def _created_at() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _receipt_common(
    report: ScanReport,
    threshold: Severity,
    status: str,
    reasons: list[str],
    report_sha256: str,
) -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "receipt_type": "sharelint.pack",
        "status": status,
        "tool": {"name": "sharelint", "version": report.tool_version},
        "created_at": _created_at(),
        "source": _source_identity(report),
        "policy": _policy_document(report, threshold),
        "summary": report.summary(threshold),
        "report_sha256": report_sha256,
        "reasons": list(reasons),
    }


def _receipt_document(
    source_report: ScanReport,
    verified: ScanReport,
    archive_sha256: str,
    archive_size: int,
    files: list[dict[str, Any]],
    threshold: Severity,
    report_sha256: str,
) -> dict[str, Any]:
    document = _receipt_common(verified, threshold, "packed", [], report_sha256)
    document["source"] = _source_identity(source_report)
    document.update(
        {
            "archive": {
                "format": "zip",
                "size": archive_size,
                "sha256": archive_sha256,
                "profile": "deterministic-zip-v1",
            },
            "files": files,
            "verification": {
                "coverage_complete": True,
                "reopened_and_rescanned": True,
                "manifest_matched": True,
            },
            "claim": (
                f"0 policy-blocking findings across {len(verified.surfaces)} surface records; "
                "this receipt is not a guarantee that the archive contains no sensitive data"
            ),
        }
    )
    return document


def _blocked_receipt_document(
    report: ScanReport,
    reasons: list[str],
    threshold: Severity,
    report_sha256: str,
) -> dict[str, Any]:
    document = _receipt_common(report, threshold, "blocked", reasons, report_sha256)
    document["claim"] = "No archive was created because the ShareLint pack policy did not pass"
    return document


def _companion_report_path(receipt_path: Path) -> Path:
    if receipt_path.name.lower().endswith(".json"):
        return receipt_path.with_name(f"{receipt_path.name[:-5]}.report.json")
    return Path(f"{receipt_path}.report.json")


def _write_bytes(path: Path, payload: bytes, kind: str) -> _PublishedFile:
    if path.exists():
        raise PackError(f"refusing to overwrite an existing {kind}")
    if not path.parent.exists():
        raise PackError(f"{kind} directory does not exist")
    temporary: Path | None = None
    published = False
    try:
        with tempfile.NamedTemporaryFile(
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=path.parent,
            delete=False,
            mode="wb",
        ) as handle:
            temporary = Path(handle.name)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
            identity = os.fstat(handle.fileno())
        os.link(temporary, path)
        published = True
        return _PublishedFile(
            temporary,
            identity.st_dev,
            identity.st_ino,
            len(payload),
            hashlib.sha256(payload).hexdigest(),
        )
    except FileExistsError as exc:
        raise PackError(f"refusing to overwrite an existing {kind}") from exc
    except OSError as exc:
        raise PackError(f"{kind} could not be written atomically") from exc
    finally:
        if temporary is not None and not published:
            with suppress(OSError):
                temporary.unlink(missing_ok=True)


def _write_document(path: Path, document: dict[str, Any]) -> _PublishedFile:
    payload = (json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )
    return _write_bytes(path, payload, "receipt")


def _release_anchor(publication: _PublishedFile | None) -> None:
    if publication is not None:
        with suppress(OSError):
            publication.anchor.unlink(missing_ok=True)


def _unlink_published(path: Path | None, publication: _PublishedFile | None) -> None:
    if path is None or publication is None:
        return
    try:
        current = path.stat(follow_symlinks=False)
        anchor = publication.anchor.stat(follow_symlinks=False)
        expected = (publication.device, publication.inode)
        if (current.st_dev, current.st_ino) == expected == (anchor.st_dev, anchor.st_ino):
            path.unlink()
    except OSError:
        pass
    finally:
        _release_anchor(publication)


def _publication_matches(path: Path, publication: _PublishedFile) -> bool:
    expected_identity = (publication.device, publication.inode)
    try:
        current = path.stat(follow_symlinks=False)
        anchor = publication.anchor.stat(follow_symlinks=False)
        if (
            (current.st_dev, current.st_ino) != expected_identity
            or (anchor.st_dev, anchor.st_ino) != expected_identity
            or current.st_size != publication.size
            or anchor.st_size != publication.size
        ):
            return False
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(publication.anchor, flags)
        digest = hashlib.sha256()
        consumed = 0
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if (opened.st_dev, opened.st_ino) != expected_identity:
                return False
            while chunk := stream.read(64 * 1024):
                consumed += len(chunk)
                if consumed > publication.size:
                    return False
                digest.update(chunk)
            after = os.fstat(stream.fileno())
        for published_path in (path, publication.anchor):
            xattr_status = probe_extended_attributes(published_path)
            if xattr_status not in {
                ExtendedAttributeStatus.ABSENT,
                ExtendedAttributeStatus.NOT_APPLICABLE,
            }:
                return False
            stream_status = inspect_windows_streams(
                published_path,
                is_directory=False,
            )
            if stream_status not in {
                WindowsStreamStatus.SCANNED,
                WindowsStreamStatus.NOT_APPLICABLE,
            }:
                return False
        final = path.stat(follow_symlinks=False)
        final_anchor = publication.anchor.stat(follow_symlinks=False)
    except OSError:
        return False
    return (
        consumed == publication.size
        and digest.hexdigest() == publication.sha256
        and (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns)
        == (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        and (final.st_dev, final.st_ino) == expected_identity
        and (final_anchor.st_dev, final_anchor.st_ino) == expected_identity
    )


def _commit_publications(publications: list[tuple[Path, _PublishedFile]]) -> None:
    if not all(_publication_matches(path, publication) for path, publication in publications):
        for path, publication in reversed(publications):
            _unlink_published(path, publication)
        raise PackError("published files changed before the pack transaction committed")
    for _path, publication in publications:
        _release_anchor(publication)


def _publish_without_overwrite(
    temporary: Path,
    destination: Path,
    archive_sha256: str,
    archive_size: int,
) -> _PublishedFile:
    try:
        identity = temporary.stat(follow_symlinks=False)
    except OSError as exc:
        raise PackError("completed archive could not be inspected for publication") from exc
    if identity.st_size != archive_size:
        raise PackError("completed archive changed before publication")
    try:
        os.link(temporary, destination)
    except FileExistsError as exc:
        raise PackError("refusing to overwrite an existing output") from exc
    except OSError as exc:
        raise PackError("completed archive could not be published atomically") from exc
    return _PublishedFile(
        temporary,
        identity.st_dev,
        identity.st_ino,
        archive_size,
        archive_sha256,
    )


def _write_blocked_evidence(
    report: ScanReport,
    reasons: list[str],
    threshold: Severity,
    receipt_path: Path | None,
    report_path: Path | None,
) -> tuple[Path | None, Path | None]:
    if receipt_path is None or report_path is None:
        return None, None
    report_bytes = _report_bytes(report, threshold)
    report_publication = _write_bytes(report_path, report_bytes, "report")
    receipt_publication: _PublishedFile | None = None
    try:
        receipt_publication = _write_document(
            receipt_path,
            _blocked_receipt_document(
                report,
                reasons,
                threshold,
                _report_sha256(report_bytes),
            ),
        )
    except BaseException:
        _unlink_published(receipt_path, receipt_publication)
        _unlink_published(report_path, report_publication)
        raise
    if receipt_publication is None:  # pragma: no cover - write success always returns a handle
        _unlink_published(report_path, report_publication)
        raise PackError("receipt publication was not recorded")
    _commit_publications([(report_path, report_publication), (receipt_path, receipt_publication)])
    return receipt_path, report_path


def _policy_reasons(report: ScanReport, threshold: Severity) -> list[str]:
    reasons: list[str] = []
    if report.count_at_or_above(threshold):
        reasons.append("blocking_findings")
    if report.has_coverage_gaps:
        reasons.append("coverage_incomplete")
    return reasons


def pack(
    target: str | os.PathLike[str],
    output: str | os.PathLike[str],
    *,
    receipt: str | os.PathLike[str] | None = None,
    report_output: str | os.PathLike[str] | None = None,
    write_receipt: bool = True,
    fail_on: Severity = Severity.HIGH,
) -> PackedArtifact:
    source = Path(target)
    destination = Path(output)
    receipt_path = (
        Path(receipt)
        if receipt is not None
        else Path(f"{destination}.sharelint.json")
        if write_receipt
        else None
    )
    if receipt is not None and not write_receipt:
        raise PackError("receipt cannot be combined with disabled receipt output")
    if report_output is not None and receipt_path is None:
        raise PackError("report output requires receipt output")
    report_path = (
        Path(report_output)
        if report_output is not None
        else _companion_report_path(receipt_path)
        if receipt_path is not None
        else None
    )
    if not source.exists():
        raise ScanInputError("target does not exist")
    if destination.exists():
        raise PackError("refusing to overwrite an existing output")
    if not destination.parent.exists():
        raise PackError("output directory does not exist")
    if receipt_path is not None and receipt_path.exists():
        raise PackError("refusing to overwrite an existing receipt")
    if report_path is not None and report_path.exists():
        raise PackError("refusing to overwrite an existing report")
    output_paths = [destination]
    if receipt_path is not None:
        output_paths.append(receipt_path)
    if report_path is not None:
        output_paths.append(report_path)
    if len({path.resolve() for path in output_paths}) != len(output_paths):
        raise PackError("output, receipt, and report must use different paths")
    if source.is_dir():
        try:
            destination.resolve().relative_to(source.resolve())
        except ValueError:
            pass
        else:
            raise PackError("output must be outside the source directory")
        if receipt_path is not None:
            try:
                receipt_path.resolve().relative_to(source.resolve())
            except ValueError:
                pass
            else:
                raise PackError("receipt must be outside the source directory")
        if report_path is not None:
            try:
                report_path.resolve().relative_to(source.resolve())
            except ValueError:
                pass
            else:
                raise PackError("report must be outside the source directory")

    initial = scan(source)
    reasons = _policy_reasons(initial, fail_on)
    if reasons:
        blocked_receipt: Path | None = None
        blocked_report: Path | None = None
        if receipt is not None:
            blocked_receipt, blocked_report = _write_blocked_evidence(
                initial,
                reasons,
                fail_on,
                receipt_path,
                report_path,
            )
        raise PackBlocked(
            initial,
            reasons,
            receipt=blocked_receipt,
            report_output=blocked_report,
        )

    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            prefix=f".{destination.name}.",
            suffix=".tmp",
            dir=destination.parent,
            delete=False,
        ) as handle:
            temporary_path = Path(handle.name)
        with zipfile.ZipFile(temporary_path, "w", allowZip64=True) as archive:
            archive.comment = b"ShareLint deterministic-zip-v1"
            source_write = _write_source(archive, source, initial.limits)

        if (
            source_write.target_kind != initial.target_kind
            or source_write.target_sha256 != initial.target_sha256
        ):
            reason_codes = ["source_changed"]
            blocked_receipt = None
            blocked_report = None
            if receipt is not None:
                blocked_receipt, blocked_report = _write_blocked_evidence(
                    initial,
                    reason_codes,
                    fail_on,
                    receipt_path,
                    report_path,
                )
            raise PackBlocked(
                initial,
                reason_codes,
                receipt=blocked_receipt,
                report_output=blocked_report,
            )

        files = source_write.files

        archive_sha256, archive_size = _sha256_file(
            temporary_path,
            initial.limits.max_file_bytes,
        )
        reopened_files = _manifest_from_zip(temporary_path, initial.limits)
        if reopened_files != files:
            raise PackError("completed archive manifest did not match the bytes written")

        verified = scan(
            temporary_path,
            limits=initial.limits,
            logical_name=destination.name,
        )
        verification_reasons = _policy_reasons(verified, fail_on)
        if verification_reasons:
            reason_codes = ["artifact_rescan_failed", *verification_reasons]
            blocked_receipt = None
            blocked_report = None
            if receipt is not None:
                blocked_receipt, blocked_report = _write_blocked_evidence(
                    verified,
                    reason_codes,
                    fail_on,
                    receipt_path,
                    report_path,
                )
            raise PackBlocked(
                verified,
                reason_codes,
                receipt=blocked_receipt,
                report_output=blocked_report,
            )

        source_after = scan(source, limits=initial.limits)
        source_after_reasons = _policy_reasons(source_after, fail_on)
        if (
            source_after.target_kind != initial.target_kind
            or source_after.target_sha256 != initial.target_sha256
            or source_after_reasons
        ):
            reason_codes = ["source_changed", *source_after_reasons]
            blocked_receipt = None
            blocked_report = None
            if receipt is not None:
                blocked_receipt, blocked_report = _write_blocked_evidence(
                    source_after,
                    reason_codes,
                    fail_on,
                    receipt_path,
                    report_path,
                )
            raise PackBlocked(
                source_after,
                reason_codes,
                receipt=blocked_receipt,
                report_output=blocked_report,
            )

        report_bytes = _report_bytes(verified, fail_on)
        document = _receipt_document(
            initial,
            verified,
            archive_sha256,
            archive_size,
            files,
            fail_on,
            _report_sha256(report_bytes),
        )
        archive_publication = _publish_without_overwrite(
            temporary_path,
            destination,
            archive_sha256,
            archive_size,
        )
        report_publication: _PublishedFile | None = None
        receipt_publication: _PublishedFile | None = None
        if receipt_path is not None:
            try:
                if report_path is None:  # pragma: no cover - guarded during path setup
                    raise PackError("report path was not configured")
                report_publication = _write_bytes(report_path, report_bytes, "report")
                receipt_publication = _write_document(receipt_path, document)
            except BaseException:
                _unlink_published(receipt_path, receipt_publication)
                _unlink_published(report_path, report_publication)
                _unlink_published(destination, archive_publication)
                raise
        publications = [(destination, archive_publication)]
        if receipt_path is not None:
            if report_path is None or report_publication is None or receipt_publication is None:
                _unlink_published(receipt_path, receipt_publication)
                _unlink_published(report_path, report_publication)
                _unlink_published(destination, archive_publication)
                raise PackError("pack transaction outputs were not fully published")
            publications.extend(
                [(report_path, report_publication), (receipt_path, receipt_publication)]
            )
        _commit_publications(publications)
        temporary_path = None
        return PackedArtifact(
            output=destination,
            receipt=receipt_path,
            report_output=report_path,
            report=verified,
            archive_sha256=archive_sha256,
            archive_size=archive_size,
            files=tuple(files),
        )
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
