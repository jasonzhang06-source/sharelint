"""Explicit, data-only policy configuration. No implicit project-file discovery."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .input_io import read_document
from .models import ScanLimits, Severity

MAX_CONFIG_BYTES = 64 * 1024
PROFILE_NAME = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
BUILTIN_PROFILES = {
    "default": {"fail_on": "high", "strict": False},
    "public": {"fail_on": "medium", "strict": True},
    "strict": {"fail_on": "low", "strict": True},
}
CONFIG_TEMPLATE = """# ShareLint configuration is loaded only with --config.
schema_version = 1
default_profile = "default"

[scan]
fail_on = "high"
strict = false

[limits]
max_file_bytes = 67108864
max_member_bytes = 33554432
max_total_bytes = 268435456
max_archive_depth = 4
max_archive_members = 10000
max_compression_ratio = 200.0
max_text_chars = 8000000
max_xml_elements = 100000
max_findings = 10000

# Named profiles inherit [scan] and [limits]. Built-in names are reserved.
[profiles.client]
fail_on = "medium"
strict = true
"""


class ConfigurationError(ValueError):
    """A requested configuration or policy is invalid; never echo its content."""


@dataclass(frozen=True, slots=True)
class ScanSettings:
    profile: str
    fail_on: Severity
    strict: bool
    limits: ScanLimits

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0.0",
            "profile": self.profile,
            "fail_on": self.fail_on.value,
            "strict": self.strict,
            "pack_requires_complete_coverage": True,
            "limits": self.limits.to_dict(),
        }


def _mapping(value: Any, allowed: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or not set(value).issubset(allowed):
        raise ConfigurationError("configuration contains an unknown key or invalid table")
    return value


def _profile(value: Any) -> str:
    if not isinstance(value, str) or PROFILE_NAME.fullmatch(value) is None:
        raise ConfigurationError("profile names must be bounded lowercase identifiers")
    return value


def _scan_fields(value: Any, *, with_limits: bool = False) -> dict[str, Any]:
    fields = _mapping(
        value, {"fail_on", "strict", "limits"} if with_limits else {"fail_on", "strict"}
    )
    if "fail_on" in fields:
        try:
            Severity(fields["fail_on"])
        except (ValueError, TypeError) as exc:
            raise ConfigurationError("configured fail_on is not a supported severity") from exc
    if "strict" in fields and type(fields["strict"]) is not bool:
        raise ConfigurationError("configured strict must be a boolean")
    if "limits" in fields:
        _limits(fields["limits"])
    return fields


def _limits(value: Any) -> dict[str, Any]:
    fields = _mapping(value, set(ScanLimits().to_dict()))
    try:
        ScanLimits(**fields)
    except (ValueError, TypeError) as exc:
        raise ConfigurationError(
            "configured limits must be finite positive numbers of the correct type"
        ) from exc
    return fields


def resolve_settings(
    *,
    config: Path | None = None,
    profile: str | None = None,
    fail_on: Severity | None = None,
    strict: bool | None = None,
) -> ScanSettings:
    document: dict[str, Any] = {}
    if config is not None:
        try:
            document = tomllib.loads(read_document(config, MAX_CONFIG_BYTES).decode("utf-8"))
        except (tomllib.TOMLDecodeError, UnicodeDecodeError, RecursionError) as exc:
            raise ConfigurationError("configuration must be a valid UTF-8 TOML document") from exc
        _mapping(document, {"schema_version", "default_profile", "scan", "limits", "profiles"})
        if type(document.get("schema_version")) is not int or document["schema_version"] != 1:
            raise ConfigurationError("configuration requires schema_version = 1")
    base: dict[str, Any] = {**BUILTIN_PROFILES["default"], **_scan_fields(document.get("scan", {}))}
    limits = {**ScanLimits().to_dict(), **_limits(document.get("limits", {}))}
    profiles = document.get("profiles", {})
    if not isinstance(profiles, dict) or len(profiles) > 64:
        raise ConfigurationError("configuration profiles must be a table of at most 64 profiles")
    for name, value in profiles.items():
        _profile(name)
        if name in BUILTIN_PROFILES:
            raise ConfigurationError("configuration cannot redefine a built-in profile")
        _scan_fields(value, with_limits=True)
    selected = _profile(
        profile if profile is not None else document.get("default_profile", "default")
    )
    if selected in BUILTIN_PROFILES:
        if selected != "default":
            base.update(BUILTIN_PROFILES[selected])
    elif selected in profiles:
        base.update(_scan_fields(profiles[selected], with_limits=True))
        limits.update(base.pop("limits", {}))
    else:
        raise ConfigurationError("unknown profile; use config show to inspect the selected policy")
    # Validate even an unused default profile so malformed control documents fail closed.
    default_profile = _profile(document.get("default_profile", "default"))
    if default_profile not in BUILTIN_PROFILES and default_profile not in profiles:
        raise ConfigurationError("configuration names an undefined default profile")
    return ScanSettings(
        profile=selected,
        fail_on=fail_on if fail_on is not None else Severity(base["fail_on"]),
        strict=strict if strict is not None else base["strict"],
        limits=ScanLimits(**limits),
    )
