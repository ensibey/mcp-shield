"""Tests for canonical MCP security rule registry and risk scoring models."""

from mcp_shield.models import ScanReport, SecurityFinding
from mcp_shield.rules import RULE_REGISTRY


def test_rule_registry_contains_10_unique_mcp_rules():
    assert len(RULE_REGISTRY) == 10
    slugs = {r.slug for r in RULE_REGISTRY.values()}
    assert len(slugs) == 10
    for rule in RULE_REGISTRY.values():
        assert rule.owasp_llm.startswith("LLM")


def test_scan_report_risk_scoring():
    empty = ScanReport()
    assert empty.risk_score == 0
    assert empty.risk_level == "SAFE"

    crit = ScanReport(
        findings=[
            SecurityFinding("MS001", "tool-poisoning", "CRITICAL", "evil", "desc", "poisoned", "remove"),
            SecurityFinding("MS006", "unpinned-package", "HIGH", "evil", "args", "unpinned", "pin"),
        ]
    )
    assert crit.risk_score == 48
    assert crit.risk_level == "CRITICAL"
