"""
Command-line interface for mcp-shield.

Usage:
    mcp-shield scan                          # Auto-discover & scan local MCP configs
    mcp-shield scan path/to/mcp.json         # Scan a specific MCP config or manifest
    mcp-shield scan mcp.json --live          # Spawn stdio servers & audit live tools/list
    mcp-shield scan mcp.json --format sarif --output results.sarif
    mcp-shield discover                      # List discovered MCP configs on this machine
    mcp-shield rules                         # List all 10 security rules (MS001-MS010)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from mcp_shield.discovery import discover_mcp_configs
from mcp_shield.engine import MCPShieldEngine
from mcp_shield.models import SEVERITY_ORDER, ScanReport
from mcp_shield.reporting import render_report
from mcp_shield.rules import RULE_REGISTRY


def _exceeds_fail_threshold(report: ScanReport, fail_on: str) -> bool:
    if fail_on == "NONE" or not report.findings:
        return False
    threshold = SEVERITY_ORDER.get(fail_on, 3)
    return any(SEVERITY_ORDER.get(f.severity.upper(), 1) >= threshold for f in report.findings)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="mcp-shield",
        description="Zero-dependency security scanner for Model Context Protocol (MCP) servers.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Scan MCP config file(s) or auto-discovered local client configs.")
    p_scan.add_argument("targets", nargs="*", help="Path(s) to mcp.json / claude_desktop_config.json (auto-discovers if omitted)")
    p_scan.add_argument("--live", action="store_true", help="Run sandboxed JSON-RPC tools/list handshake against stdio servers")
    p_scan.add_argument("--format", choices=["text", "json", "sarif", "markdown"], default="text")
    p_scan.add_argument("--fail-on", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL", "NONE"], default="HIGH")
    p_scan.add_argument("--output", default=None, help="Write report output to a file path")

    sub.add_parser("discover", help="List all auto-discovered MCP client config files on this machine.")
    sub.add_parser("rules", help="List all canonical MCP security rules (MS001–MS010).")

    args = parser.parse_args(argv)

    if args.command == "rules":
        for rule in RULE_REGISTRY.values():
            print(f"{rule.rule_id} [{rule.default_severity:<8}] ({rule.slug}) — {rule.name} [{rule.owasp_llm}]")
        return 0

    if args.command == "discover":
        found = discover_mcp_configs()
        if not found:
            print("No local MCP configuration files discovered.")
            return 0
        for label, path in found:
            print(f"{label:<22} {path}")
        return 0

    if args.command == "scan":
        paths: List[Path] = []
        if args.targets:
            for raw in args.targets:
                p = Path(raw)
                if not p.exists():
                    print(f"error: file not found: {p}", file=sys.stderr)
                    return 2
                paths.append(p)
        else:
            discovered = discover_mcp_configs()
            if not discovered:
                print("No MCP configs found automatically. Pass an explicit path: mcp-shield scan path/to/mcp.json")
                return 0
            paths = [p for _, p in discovered]

        engine = MCPShieldEngine()
        report = engine.scan_files(paths, probe_live=args.live)
        rendered = render_report(report, fmt=args.format)

        if args.output:
            out_path = Path(args.output)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(rendered, encoding="utf-8")
        else:
            print(rendered)

        return 1 if _exceeds_fail_threshold(report, args.fail_on) else 0

    return 2


if __name__ == "__main__":
    sys.exit(main())
