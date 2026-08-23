"""Path-name checks that run before file content is opened."""

from __future__ import annotations

import re

from ..context import ScanContext
from ..models import SurfaceStatus
from ..privacy import mask_evidence

EMAIL_RE = re.compile(r"(?i)[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+")
HOME_RE = re.compile(
    r"(?i)(?:^|[/\\])(?:home|users)[/\\][^/\\\s]+(?:[/\\]|$)|[A-Z]:[/\\]Users[/\\][^/\\\s]+"
)
SENSITIVE_LABEL_RE = re.compile(
    r"(?i)(?<![^._\-/ ])(?:confidential|nda|passport|patient|payroll|salary|secret|tax[-_ ]?return)(?![^._\-/ ])"
)
_SURROGATE_RE = re.compile(r"[\ud800-\udfff]+")
_RESERVED_PATH_REF_RE = re.compile(r"\[path-ref:[^\]]*\]", re.IGNORECASE)
_UNSAFE_DISPLAY_RE = re.compile(r"[\x00-\x1f\x7f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]+")


def redact_path(name: str) -> str:
    """Return a stable logical path that cannot repeat detected path evidence."""

    redacted = EMAIL_RE.sub(lambda match: mask_evidence(match.group(0), "email"), name)
    redacted = HOME_RE.sub("<local-home-path>/", redacted)
    redacted = SENSITIVE_LABEL_RE.sub("<sensitive-label>", redacted)
    redacted = _SURROGATE_RE.sub("<invalid-unicode>", redacted)
    redacted = _UNSAFE_DISPLAY_RE.sub("<control>", redacted)
    redacted = _RESERVED_PATH_REF_RE.sub("<literal-path-ref>", redacted)
    return redacted


def scan_name(name: str, source_chain: tuple[str, ...], context: ScanContext) -> None:
    if _SURROGATE_RE.search(name):
        context.add_finding(
            "SL.SCAN.UNSUPPORTED_CONTENT",
            source_chain,
            "path encoding",
            "path contains undecodable filesystem bytes",
        )
        context.add_surface(
            source_chain,
            "path-name",
            SurfaceStatus.PARTIAL,
            0,
            "path",
            "path contains undecodable filesystem bytes",
        )
    for match in EMAIL_RE.finditer(name):
        context.add_finding(
            "SL.PATH.EMAIL_IN_NAME",
            source_chain,
            "path name",
            match.group(0),
            evidence_kind="email",
        )
    for match in HOME_RE.finditer(name):
        context.add_finding(
            "SL.PATH.LOCAL_HOME",
            source_chain,
            "path name",
            match.group(0),
            evidence_kind="path",
        )
    for match in SENSITIVE_LABEL_RE.finditer(name):
        context.add_finding(
            "SL.PATH.SENSITIVE_LABEL",
            source_chain,
            "path name",
            match.group(0),
        )
