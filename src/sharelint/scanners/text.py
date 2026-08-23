"""Deterministic text, PII, credential, and local-path detectors."""

from __future__ import annotations

import math
import re
from collections.abc import Iterator

from ..context import ScanContext

PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]{0,200}?",
    re.IGNORECASE,
)
AWS_RE = re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])")
GITHUB_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:gh[opsu]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{40,255})"
)
JWT_RE = re.compile(
    r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}(?![A-Za-z0-9_-])"
)
GENERIC_SECRET_RE = re.compile(
    r"(?i)(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password|passwd|secret)"
    r"\s*[=:]\s*['\"]?([A-Za-z0-9_./+\-=]{12,256})"
)
EMAIL_RE = re.compile(
    r"(?i)(?<![\w.+-])([a-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63})+)(?![\w.-])"
)
SSN_RE = re.compile(r"(?<!\d)(?!000|666|9\d\d)\d{3}[- ](?!00)\d{2}[- ](?!0000)\d{4}(?!\d)")
CARD_RE = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")
HOME_RE = re.compile(
    r"(?i)(?:/(?:home|Users)/[^/\s'\"<>]+(?:/[^\s'\"<>]*)?|[A-Z]:\\Users\\[^\\\s'\"<>]+(?:\\[^\s'\"<>]*)?)"
)


def _character_classes(value: str) -> int:
    return sum(
        (
            any(char.islower() for char in value),
            any(char.isupper() for char in value),
            any(char.isdigit() for char in value),
            any(not char.isalnum() for char in value),
        )
    )


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {character: value.count(character) for character in set(value)}
    return -sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values())


def _likely_real_secret(value: str) -> bool:
    lowered = value.lower().strip("-_./")
    placeholders = {
        "changeme",
        "example",
        "examplekey",
        "notasecret",
        "placeholder",
        "redacted",
        "replace_me",
        "replace-this",
        "testpassword",
        "your_api_key",
        "your-token-here",
    }
    return (
        len(value) >= 16
        and lowered not in placeholders
        and "xxxx" not in lowered
        and _character_classes(value) >= 2
        and _entropy(value) >= 3.0
    )


def _luhn_valid(value: str) -> bool:
    digits = [int(character) for character in value if character.isdigit()]
    if not 13 <= len(digits) <= 19 or len(set(digits)) == 1:
        return False
    total = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def _matches(
    pattern: re.Pattern[str],
    text: str,
) -> Iterator[tuple[re.Match[str], int]]:
    line = 1
    cursor = 0
    for match in pattern.finditer(text):
        line += text.count("\n", cursor, match.start())
        cursor = match.start()
        yield match, line


def scan_text(
    text: str,
    source_chain: tuple[str, ...],
    context: ScanContext,
    *,
    location_prefix: str = "",
) -> None:
    text = text[: context.limits.max_text_chars]

    def location(line: int) -> str:
        item = f"line {line}"
        return f"{location_prefix}, {item}" if location_prefix else item

    specifications = (
        ("SL.SECRET.PRIVATE_KEY", PRIVATE_KEY_RE, "private_key"),
        ("SL.SECRET.AWS_ACCESS_KEY", AWS_RE, "secret"),
        ("SL.SECRET.GITHUB_TOKEN", GITHUB_RE, "secret"),
        ("SL.SECRET.JWT", JWT_RE, "token"),
        ("SL.PII.EMAIL", EMAIL_RE, "email"),
        ("SL.PII.US_SSN", SSN_RE, "ssn"),
        ("SL.PATH.LOCAL_HOME", HOME_RE, "path"),
    )
    for rule_id, pattern, evidence_kind in specifications:
        for match, line in _matches(pattern, text):
            if context.finding_limit_reached:
                return
            evidence = match.group(1) if match.lastindex else match.group(0)
            context.add_finding(
                rule_id,
                source_chain,
                location(line),
                evidence,
                evidence_kind=evidence_kind,
            )

    for match, line in _matches(GENERIC_SECRET_RE, text):
        if context.finding_limit_reached:
            return
        evidence = match.group(1)
        if _likely_real_secret(evidence):
            context.add_finding(
                "SL.SECRET.GENERIC_ASSIGNMENT",
                source_chain,
                location(line),
                evidence,
                evidence_kind="secret",
            )

    for match, line in _matches(CARD_RE, text):
        if context.finding_limit_reached:
            return
        evidence = match.group(0)
        if _luhn_valid(evidence):
            context.add_finding(
                "SL.PII.PAYMENT_CARD",
                source_chain,
                location(line),
                evidence,
                evidence_kind="card",
            )
