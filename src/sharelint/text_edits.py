"""Conservative, bounded UTF-8 text transformations; never an original-file writer."""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from .documents import array, choice, integer, object_fields, require
from .input_io import DocumentInputError
from .scanners.text import iter_text_matches

MAX_REDACTION_BYTES = 4 * 1024 * 1024
MAX_EDITS = 10_000
REPLACEMENT = "[REDACTED]"
REDACTION_RULES = (
    "SL.PATH.LOCAL_HOME",
    "SL.PII.EMAIL",
    "SL.PII.PAYMENT_CARD",
    "SL.PII.US_SSN",
    "SL.SECRET.AWS_ACCESS_KEY",
    "SL.SECRET.GENERIC_ASSIGNMENT",
    "SL.SECRET.GITHUB_TOKEN",
    "SL.SECRET.JWT",
)
_TOKEN_TAILS = {
    "SL.SECRET.GITHUB_TOKEN": re.compile(r"[A-Za-z0-9_]*"),
    "SL.SECRET.GENERIC_ASSIGNMENT": re.compile(r"[A-Za-z0-9_./+\-=]*"),
}


def selected_rules(rules: Iterable[str] | None) -> tuple[str, ...]:
    if rules is None:
        return REDACTION_RULES
    if isinstance(rules, (str, bytes)):
        raise DocumentInputError("redaction rules must be a sequence of supported identifiers")
    result: list[str] = []
    for index, rule in enumerate(rules):
        if index >= len(REDACTION_RULES):
            raise DocumentInputError("too many redaction rule selections")
        result.append(choice(rule, REDACTION_RULES))
    require(bool(result) and len(result) == len(set(result)))
    return tuple(sorted(result))


def decode_redaction_text(data: bytes, max_chars: int) -> str:
    if len(data) > MAX_REDACTION_BYTES:
        raise DocumentInputError("redaction input exceeds the 4 MiB hard limit")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DocumentInputError("redaction supports complete UTF-8 text only") from exc
    if len(text) > max_chars:
        raise DocumentInputError("redaction text exceeds the configured character limit")
    if any(ord(character) < 32 and character not in "\r\n\t" for character in text):
        raise DocumentInputError("redaction does not support binary or control-byte text")
    return text


def plan_edits(text: str, rules: tuple[str, ...], *, maximum: int) -> list[dict[str, Any]]:
    if type(maximum) is not int or not 1 <= maximum <= MAX_EDITS:
        raise DocumentInputError("redaction edit limit must be between 1 and 10000")
    candidates: list[dict[str, Any]] = []
    for match in iter_text_matches(text):
        if match.rule_id not in rules:
            continue
        if len(candidates) >= maximum:
            raise DocumentInputError("redaction candidate count exceeds its limit")
        end = match.end
        pattern = _TOKEN_TAILS.get(match.rule_id)
        if pattern is not None:
            tail = pattern.match(text, end)
            if tail is not None:
                end = tail.end()
        candidates.append(
            {
                "start": match.start,
                "end": end,
                "line": match.line,
                "rules": [match.rule_id],
                "replacement": REPLACEMENT,
            }
        )
    candidates.sort(key=lambda item: (item["start"], item["end"]))
    merged: list[dict[str, Any]] = []
    for candidate in candidates:
        if merged and candidate["start"] < merged[-1]["end"]:
            merged[-1]["end"] = max(merged[-1]["end"], candidate["end"])
            merged[-1]["rules"] = sorted(set(merged[-1]["rules"]) | set(candidate["rules"]))
        else:
            merged.append(candidate)
    return merged


def validate_edits(
    value: Any, *, characters: int, rules: tuple[str, ...], maximum: int
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    previous = 0
    for item in array(value, maximum=maximum):
        edit = object_fields(item, ("start", "end", "line", "rules", "replacement"), strict=True)
        start, end = integer(edit["start"]), integer(edit["end"])
        require(previous <= start < end <= characters)
        require(1 <= integer(edit["line"]) <= characters + 1)
        chosen = [choice(rule, rules) for rule in array(edit["rules"], maximum=len(rules))]
        require(bool(chosen) and chosen == sorted(set(chosen)))
        require(edit["replacement"] == REPLACEMENT)
        result.append(edit)
        previous = end
    return result


def apply_edits(text: str, edits: list[dict[str, Any]]) -> bytes:
    parts: list[str] = []
    cursor = 0
    for edit in edits:
        parts.append(text[cursor : edit["start"]])
        parts.append(REPLACEMENT)
        cursor = edit["end"]
    parts.append(text[cursor:])
    result = "".join(parts).encode("utf-8")
    if len(result) > MAX_REDACTION_BYTES:
        raise DocumentInputError("redacted output exceeds the 4 MiB hard limit")
    return result
