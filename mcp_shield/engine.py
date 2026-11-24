"""Unified MCPShieldEngine orchestrating all 4 security scanner layers."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from mcp_shield.discovery import load_mcp_config
from mcp_shield.live_client import probe_stdio_mcp_tools
from mcp_shield.models import ScanReport, SecurityFinding
from mcp_shield.scanners.config_audit import scan_server_config
from mcp_shield.scanners.shadowing import scan_tool_shadowing
from mcp_shield.scanners.tool_poisoning import scan_tool_poisoning


class MCPShieldEngine:
    """Runs 4-layer deterministic security analysis across MCP configs and tool manifests."""

    def scan_config_dict(
        self,
        servers: Dict[str, Dict[str, Any]],
        source_file: str = "mcp.json",
        probe_live: bool = False,
    ) -> ScanReport:
        t0 = time.perf_counter()
        findings: List[SecurityFinding] = []
        all_tools: List[Tuple[str, Dict[str, Any], str]] = []

        for server_name, spec in servers.items():
            if not isinstance(spec, dict):
                continue
            findings.extend(scan_server_config(server_name, spec, source_file=source_file))

            declared_tools = list(spec.get("tools") or [])
            if probe_live and spec.get("command") and not declared_tools:
                declared_tools = probe_stdio_mcp_tools(
                    command=str(spec["command"]),
                    args=[str(a) for a in (spec.get("args") or [])],
                    env=spec.get("env") if isinstance(spec.get("env"), dict) else None,
                )

            for tool in declared_tools:
                if isinstance(tool, dict):
                    all_tools.append((server_name, tool, source_file))
                    findings.extend(scan_tool_poisoning(server_name, tool, source_file=source_file))

        findings.extend(scan_tool_shadowing(all_tools))
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        return ScanReport(
            source_files=[source_file],
            servers_scanned=len(servers),
            tools_scanned=len(all_tools),
            elapsed_ms=elapsed_ms,
            findings=findings,
        )

    def scan_files(self, paths: Sequence[Path], probe_live: bool = False) -> ScanReport:
        t0 = time.perf_counter()
        merged_findings: List[SecurityFinding] = []
        all_tools: List[Tuple[str, Dict[str, Any], str]] = []
        source_files: List[str] = []
        total_servers = 0

        for path in paths:
            source_label = path.as_posix()
            source_files.append(source_label)
            servers = load_mcp_config(path)
            total_servers += len(servers)

            for server_name, spec in servers.items():
                merged_findings.extend(scan_server_config(server_name, spec, source_file=source_label))
                declared_tools = list(spec.get("tools") or [])
                if probe_live and spec.get("command") and not declared_tools:
                    declared_tools = probe_stdio_mcp_tools(
                        command=str(spec["command"]),
                        args=[str(a) for a in (spec.get("args") or [])],
                        env=spec.get("env") if isinstance(spec.get("env"), dict) else None,
                    )
                for tool in declared_tools:
                    if isinstance(tool, dict):
                        all_tools.append((server_name, tool, source_label))
                        merged_findings.extend(scan_tool_poisoning(server_name, tool, source_file=source_label))

        # Cross-config & cross-server shadowing check across all scanned files
        merged_findings.extend(scan_tool_shadowing(all_tools))
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        return ScanReport(
            source_files=source_files,
            servers_scanned=total_servers,
            tools_scanned=len(all_tools),
            elapsed_ms=elapsed_ms,
            findings=merged_findings,
        )
