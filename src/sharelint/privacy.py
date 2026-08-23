"""Privacy-preserving evidence masking and report-scoped correlation."""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass, field

_EMAIL_RE = re.compile(r"(?P<local>[^@\s]{1,64})@(?P<domain>[^@\s]{1,255})")


def _edge_mask(value: str, visible: int = 2) -> str:
    if not value:
        return "<present>"
    if len(value) <= visible * 2:
        return "•" * min(8, len(value))
    return f"{value[:visible]}{'•' * min(12, len(value) - visible * 2)}{value[-visible:]}"


def mask_evidence(value: str, kind: str = "generic") -> str:
    """Return a bounded preview that never includes a complete matched value."""

    compact = " ".join(value.strip().split())[:512]
    if not compact:
        return "<present>"
    if kind == "email":
        match = _EMAIL_RE.fullmatch(compact)
        if match:
            local = match.group("local")
            domain = match.group("domain")
            suffix = domain.rsplit(".", 1)[-1] if "." in domain else ""
            return f"{local[:1]}•••@•••{('.' + suffix) if suffix else ''}"
    if kind in {"secret", "token", "private_key"}:
        return f"<{kind.replace('_', '-')}:{len(compact)} chars>"
    if kind in {"card", "ssn"}:
        digits = "".join(character for character in compact if character.isdigit())
        return f"<redacted:{len(digits)} digits>"
    if kind == "path":
        normalized = compact.replace("\\", "/")
        parts = normalized.split("/")
        if len(parts) >= 3:
            return "/".join([parts[0], "…", _edge_mask(parts[-1], 1)])
    return _edge_mask(compact)


@dataclass(slots=True)
class EvidenceProtector:
    """Correlate duplicate evidence without publishing a reusable value hash.

    A fresh HMAC key is generated for each report and discarded. The public scope
    identifier tells consumers that fingerprints from different reports must not be
    compared.
    """

    key: bytes = field(default_factory=lambda: secrets.token_bytes(32), repr=False)
    scope: str = field(default_factory=lambda: secrets.token_hex(8))

    def fingerprint(self, rule_id: str, value: str) -> str:
        digest = hmac.new(
            self.key,
            f"{rule_id}\0{value}".encode("utf-8", errors="replace"),
            hashlib.sha256,
        ).hexdigest()
        return f"hmac-sha256:{digest[:24]}"
