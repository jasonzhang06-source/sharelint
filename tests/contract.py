"""Small assertions for the public JSON/SARIF contracts, not internals."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any

SEVERITIES = ("info", "low", "medium", "high", "critical")


def findings(payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    value = payload.get("findings")
    assert isinstance(value, list), "scan JSON must contain a 'findings' array"
    assert all(isinstance(item, dict) for item in value), "every finding must be an object"
    return value


def assert_scan_contract(payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    assert payload.get("schema_version") == "1.0.0", "scan JSON needs schema_version 1.0.0"
    result = findings(payload)
    summary = payload.get("summary")
    assert isinstance(summary, dict), "scan JSON must contain a summary object"
    assert summary.get("total_findings") == len(result), (
        "summary.total_findings must equal findings length"
    )
    for finding in result:
        assert isinstance(finding.get("rule_id"), str) and finding["rule_id"]
        assert finding.get("severity") in SEVERITIES
        assert isinstance(finding.get("location"), str) and finding["location"]
        chain = finding.get("source_chain")
        assert isinstance(chain, list) and chain
        assert all(isinstance(item, str) and item for item in chain)
    return result


def chain_contains_in_order(chain: Sequence[str], expected: Iterable[str]) -> bool:
    """Match logical archive components without prescribing URI punctuation."""

    position = 0
    flattened = "\n".join(chain).replace("\\", "/")
    for component in expected:
        index = flattened.find(component.replace("\\", "/"), position)
        if index < 0:
            return False
        position = index + len(component)
    return True


def sarif_results(payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    assert payload.get("version") == "2.1.0"
    runs = payload.get("runs")
    assert isinstance(runs, list) and len(runs) == 1
    tool = runs[0].get("tool", {}).get("driver", {})
    assert str(tool.get("name", "")).lower() == "sharelint"
    results = runs[0].get("results")
    assert isinstance(results, list)
    assert all(isinstance(result, dict) for result in results)
    return results
