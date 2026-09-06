"""Shared, versioned policy identities for receipts and reviewed handoff plans."""

from __future__ import annotations

import hashlib
from typing import Any

from .models import ScanLimits, Severity
from .reporters import canonical_json
from .rules import RULES


def ruleset_sha256() -> str:
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


def policy_document(
    limits: ScanLimits, threshold: Severity, *, ruleset_digest: str | None = None
) -> dict[str, Any]:
    ruleset_digest = ruleset_digest or ruleset_sha256()
    descriptor = {
        "format": "sharelint-pack-policy-v1",
        "fail_on": threshold.value,
        "require_complete_coverage": True,
        "limits": limits.to_dict(),
        "ruleset_sha256": ruleset_digest,
    }
    return {
        "sha256": hashlib.sha256(canonical_json(descriptor).encode("utf-8")).hexdigest(),
        "ruleset_sha256": ruleset_digest,
        "fail_on": threshold.value,
        "require_complete_coverage": True,
        "limits": limits.to_dict(),
    }
