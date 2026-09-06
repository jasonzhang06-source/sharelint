#!/usr/bin/env python3
"""Decide whether a PyPI release needs publishing or already has identical bytes."""

from __future__ import annotations

import argparse
import email.policy
import hashlib
import json
import re
import sys
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from email.parser import BytesParser
from pathlib import Path
from typing import Any

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.normalize_sdist import (  # noqa: E402
    SdistNormalizationError,
    canonical_sdist_bytes,
)

MAX_DISTRIBUTION_BYTES = 64 * 1024 * 1024
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_METADATA_BYTES = 2 * 1024 * 1024
FETCH_ATTEMPTS = 4
SAFE_NAME = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]*\Z")
SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")


class PyPIRecoveryError(RuntimeError):
    """Raised when publication cannot safely proceed or be skipped."""


def _sha256(path: Path) -> str:
    if path.stat().st_size > MAX_DISTRIBUTION_BYTES:
        raise PyPIRecoveryError(f"distribution exceeds size budget: {path.name}")
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            total += len(chunk)
            if total > MAX_DISTRIBUTION_BYTES:
                raise PyPIRecoveryError(f"distribution exceeds size budget: {path.name}")
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_project(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _validate_metadata(content: bytes, *, project: str, version: str, source: str) -> None:
    if len(content) > MAX_METADATA_BYTES:
        raise PyPIRecoveryError(f"{source} metadata exceeds its size budget")
    try:
        message = BytesParser(policy=email.policy.default).parsebytes(content)
    except (TypeError, ValueError) as exc:
        raise PyPIRecoveryError(f"{source} metadata is invalid") from exc
    names = message.get_all("Name", [])
    versions = message.get_all("Version", [])
    if (
        len(names) != 1
        or not isinstance(names[0], str)
        or _canonical_project(names[0]) != _canonical_project(project)
        or versions != [version]
    ):
        raise PyPIRecoveryError(f"{source} metadata does not match the project and version")


def _validate_wheel(path: Path, *, project: str, version: str) -> None:
    normalized = re.sub(r"[-_.]+", "_", project).lower()
    expected_metadata = f"{normalized}-{version}.dist-info/METADATA"
    try:
        with zipfile.ZipFile(path) as archive:
            candidates = [item for item in archive.infolist() if item.filename == expected_metadata]
            if len(candidates) != 1 or candidates[0].file_size > MAX_METADATA_BYTES:
                raise PyPIRecoveryError("wheel has an invalid METADATA inventory")
            _validate_metadata(
                archive.read(candidates[0]), project=project, version=version, source="wheel"
            )
    except zipfile.BadZipFile as exc:
        raise PyPIRecoveryError("wheel is not a valid ZIP archive") from exc


def _validate_sdist(path: Path, *, project: str, version: str) -> None:
    normalized = _canonical_project(project)
    root = f"{normalized}-{version}"
    try:
        canonical = canonical_sdist_bytes(path, project=project, version=version)
    except SdistNormalizationError as exc:
        raise PyPIRecoveryError("source distribution is unsafe or invalid") from exc
    if path.read_bytes() != canonical:
        raise PyPIRecoveryError("source distribution is not canonical")
    try:
        with tarfile.open(path, mode="r:gz") as archive:
            member = archive.getmember(f"{root}/PKG-INFO")
            if not member.isreg() or member.size > MAX_METADATA_BYTES:
                raise PyPIRecoveryError("source distribution has invalid PKG-INFO")
            stream = archive.extractfile(member)
            if stream is None:
                raise PyPIRecoveryError("source distribution PKG-INFO is unreadable")
            metadata = stream.read(MAX_METADATA_BYTES + 1)
    except (KeyError, tarfile.TarError) as exc:
        raise PyPIRecoveryError("source distribution lacks valid PKG-INFO") from exc
    _validate_metadata(metadata, project=project, version=version, source="source distribution")


def local_distributions(directory: Path, *, project: str, version: str) -> dict[str, str]:
    if directory.is_symlink() or not directory.is_dir():
        raise PyPIRecoveryError("distribution directory must be a real directory")
    if not SAFE_NAME.fullmatch(project) or not SAFE_NAME.fullmatch(version):
        raise PyPIRecoveryError("project or version is unsafe for local distribution validation")
    normalized_wheel = re.sub(r"[-_.]+", "_", project).lower()
    normalized_sdist = _canonical_project(project)
    expected = {
        f"{normalized_wheel}-{version}-py3-none-any.whl",
        f"{normalized_sdist}-{version}.tar.gz",
    }
    entries = sorted(directory.iterdir(), key=lambda path: path.name)
    if {path.name for path in entries} != expected or any(
        path.is_symlink() or not path.is_file() for path in entries
    ):
        raise PyPIRecoveryError("expected exactly one wheel and one source distribution")
    wheel = next(path for path in entries if path.name.endswith(".whl"))
    sdist = next(path for path in entries if path.name.endswith(".tar.gz"))
    _validate_wheel(wheel, project=project, version=version)
    _validate_sdist(sdist, project=project, version=version)
    return {path.name: _sha256(path) for path in entries}


def _remote_distributions(payload: Any, *, version: str) -> dict[str, str]:
    if not isinstance(payload, dict):
        raise PyPIRecoveryError("PyPI returned a non-object response")
    info = payload.get("info")
    urls = payload.get("urls")
    if not isinstance(info, dict) or info.get("version") != version or not isinstance(urls, list):
        raise PyPIRecoveryError("PyPI returned metadata for an unexpected release")
    remote: dict[str, str] = {}
    for item in urls:
        if not isinstance(item, dict):
            raise PyPIRecoveryError("PyPI returned an invalid distribution record")
        filename = item.get("filename")
        digests = item.get("digests")
        digest = digests.get("sha256") if isinstance(digests, dict) else None
        if (
            not isinstance(filename, str)
            or not isinstance(digest, str)
            or not SHA256.fullmatch(digest)
            or filename in remote
        ):
            raise PyPIRecoveryError("PyPI returned an invalid or duplicate distribution digest")
        remote[filename] = digest
    return remote


def publication_required(
    local: dict[str, str], remote_payload: Any | None, *, version: str
) -> bool:
    """Return true only when the version is absent; require exact bytes otherwise."""

    if remote_payload is None:
        return True
    remote = _remote_distributions(remote_payload, version=version)
    if remote != local:
        missing = sorted(set(local) - set(remote))
        unexpected = sorted(set(remote) - set(local))
        changed = sorted(name for name in set(local) & set(remote) if local[name] != remote[name])
        raise PyPIRecoveryError(
            "existing PyPI release differs from local distributions: "
            f"missing={missing!r}, unexpected={unexpected!r}, changed={changed!r}"
        )
    return False


def _fetch_release_once(project: str, version: str, *, nonce: int) -> Any | None:
    if not SAFE_NAME.fullmatch(project) or not SAFE_NAME.fullmatch(version):
        raise PyPIRecoveryError("project or version is unsafe for a PyPI request")
    base_url = (
        "https://pypi.org/pypi/"
        f"{urllib.parse.quote(project, safe='')}/{urllib.parse.quote(version, safe='')}/json"
    )
    url = f"{base_url}?sharelint_reconcile={nonce}"
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "User-Agent": "ShareLint release recovery check",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            if response.geturl() != url:
                raise PyPIRecoveryError("PyPI release lookup redirected unexpectedly")
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise PyPIRecoveryError(f"PyPI release lookup failed with HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise PyPIRecoveryError("PyPI release lookup failed") from exc
    if len(raw) > MAX_RESPONSE_BYTES:
        raise PyPIRecoveryError("PyPI release response exceeds its size budget")
    try:
        return json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PyPIRecoveryError("PyPI release response is not valid UTF-8 JSON") from exc


def reconcile_publication(
    local: dict[str, str], *, project: str, version: str, attempts: int = FETCH_ATTEMPTS
) -> str:
    """Return ``publish`` only after all queries are 404; reuse only exact bytes."""

    if attempts < 1 or attempts > 10:
        raise PyPIRecoveryError("PyPI reconciliation attempt count is invalid")
    saw_non_404_failure = False
    last_error: PyPIRecoveryError | None = None
    for attempt in range(attempts):
        try:
            payload = _fetch_release_once(project, version, nonce=time.time_ns())
            if payload is not None:
                try:
                    publication_required(local, payload, version=version)
                except PyPIRecoveryError as exc:
                    saw_non_404_failure = True
                    last_error = exc
                else:
                    return "reuse"
        except PyPIRecoveryError as exc:
            saw_non_404_failure = True
            last_error = exc
        if attempt + 1 < attempts:
            time.sleep(min(2**attempt, 4))
    if saw_non_404_failure:
        raise last_error or PyPIRecoveryError("PyPI reconciliation failed")
    return "publish"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Publish only when absent; safely skip an identical existing PyPI release."
    )
    parser.add_argument("directory", type=Path)
    parser.add_argument("--project", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--github-output", type=Path, required=True)
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    try:
        local = local_distributions(
            arguments.directory, project=arguments.project, version=arguments.version
        )
        decision = reconcile_publication(
            local, project=arguments.project, version=arguments.version
        )
        output = arguments.github_output
        if output.is_symlink() or not output.is_file():
            raise PyPIRecoveryError("GITHUB_OUTPUT must be a regular non-symlink file")
        with output.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(f"decision={decision}\n")
    except (OSError, PyPIRecoveryError) as exc:
        print(f"PyPI recovery check failed: {exc}", file=sys.stderr)
        return 1
    if decision == "publish":
        print("PyPI version is absent; trusted publication is required.")
    else:
        print("PyPI already contains the exact local distribution bytes; publication is skipped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
