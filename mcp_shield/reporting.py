"""Terminal, Markdown, JSON, and SARIF 2.1.0 report formatters for mcp-shield."""

from __future__ import annotations

import json
from typing import Any, Dict, List

from mcp_shield import __version__
from mcp_shield.models import ScanReport
from mcp_shield.rules import RULE_REGISTRY

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

SEVERITY_TO_SARIF_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}

SEVERITY_TO_SCORE = {
    "CRITICAL": "9.5",
    "HIGH": "7.5",
    "MEDIUM": "5.0",
    "LOW": "2.5",
}


def format_text_report(report: ScanReport) -> str:
    lines: List[str] = [
        f"mcp-shield v{__version__} — Scanned {len(report.source_files)} config(s) "
        f"({report.servers_scanned} server(s), {report.tools_scanned} tool(s)) in {report.elapsed_ms:.1f} ms",
        "",
    ]
    if not report.findings:
        lines.append("Result: SAFE (Risk Score: 0/100, 0 findings)")
        return "\n".join(lines)

    for f in report.findings:
        loc = f"{f.source_file} :: {f.target}"
        lines.append(f"[{f.severity:<8}] ({f.rule_id} {f.slug}) {loc}")
        lines.append(f"           {f.message}")
        lines.append(f"           Fix: {f.remediation}")

    lines.append("")
    lines.append(
        f"Risk Score: {report.risk_score}/100 ({report.risk_level}) | "
        f"{len(report.findings)} finding(s) detected"
    )
    return "\n".join(lines)


def format_markdown_report(report: ScanReport) -> str:
    lines: List[str] = [
        "## mcp-shield Security Audit Report",
        "",
        f"- **Risk Score:** `{report.risk_score}/100` (**{report.risk_level}**)",
        f"- **Scope:** {len(report.source_files)} config(s), {report.servers_scanned} server(s), {report.tools_scanned} tool(s) ({report.elapsed_ms:.1f} ms)",
        f"- **Findings:** {len(report.findings)}",
        "",
    ]
    if not report.findings:
        lines.append("No MCP security risks detected.")
        return "\n".join(lines)

    lines.extend(
        [
            "| Severity | Rule | Server | Target | Message |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ]
    )
    for f in report.findings:
        msg = f.message.replace("|", "\\|")
        lines.append(f"| **{f.severity}** | `{f.rule_id}` | `{f.server_name}` | `{f.target}` | {msg} |")
    return "\n".join(lines)


def export_sarif(report: ScanReport) -> Dict[str, Any]:
    rules_payload = [
        {
            "id": rule.rule_id,
            "name": rule.slug,
            "shortDescription": {"text": rule.name},
            "fullDescription": {"text": rule.description},
            "properties": {
                "tags": ["security", "mcp", rule.owasp_llm],
                "security-severity": SEVERITY_TO_SCORE.get(rule.default_severity, "5.0"),
            },
        }
        for rule in RULE_REGISTRY.values()
    ]

    results_payload = [
        {
            "ruleId": f.rule_id,
            "level": SEVERITY_TO_SARIF_LEVEL.get(f.severity.upper(), "warning"),
            "message": {"text": f"{f.message} Remediation: {f.remediation}"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.source_file.replace("\\", "/")},
                        "region": {"startLine": 1},
                    }
                }
            ],
            "properties": {
                "server_name": f.server_name,
                "tool_name": f.tool_name,
                "target": f.target,
                "severity": f.severity,
            },
        }
        for f in report.findings
    ]

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mcp-shield",
                        "version": __version__,
                        "informationUri": "https://github.com/ensibey/mcp-shield",
                        "rules": rules_payload,
                    }
                },
                "results": results_payload,
            }
        ],
    }


def render_report(report: ScanReport, fmt: str = "text") -> str:
    if fmt == "json":
        return json.dumps(report.to_dict(), indent=2, ensure_ascii=False)
    if fmt == "sarif":
        return json.dumps(export_sarif(report), indent=2, ensure_ascii=False)
    if fmt == "markdown":
        return format_markdown_report(report)
    return format_text_report(report)
