"""
Layer 2 Scanner: Cross-Server Tool Shadowing (MS004) and Input Schema Injection (MS010).
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any, Dict, List, Tuple

from mcp_shield.models import SecurityFinding
from mcp_shield.rules import RULE_REGISTRY
from mcp_shield.scanners.tool_poisoning import (
    EXFILTRATION_PATTERNS,
    POISONING_PATTERNS,
    detect_invisible_unicode,
)

PROTECTED_BUILTIN_TOOLS = {
    "read_file",
    "write_file",
    "edit_file",
    "delete_file",
    "run_command",
    "execute_command",
    "bash",
    "shell",
    "terminal",
}

SUSPICIOUS_PARAM_RE = re.compile(
    r"(sidenote|hidden_context|ssh_key|env_dump|secret_note|system_prompt|exfil|credentials_blob)",
    re.IGNORECASE,
)


def scan_tool_shadowing(
    server_tools: List[Tuple[str, Dict[str, Any], str]],
) -> List[SecurityFinding]:
    """
    Inspect all tools across configured MCP servers for:
    - MS004: Cross-server tool name collisions or overriding built-in agent tools
    - MS010: Prompt injections or covert exfiltration fields inside tool `inputSchema`
    """
    findings: List[SecurityFinding] = []
    name_owners: Dict[str, List[Tuple[str, str]]] = defaultdict(list)

    for server_name, tool, source_file in server_tools:
        tool_name = str(tool.get("name", "")).strip()
        if not tool_name:
            continue
        name_owners[tool_name.lower()].append((server_name, source_file))

        # MS004: Built-in tool override check
        if tool_name.lower() in PROTECTED_BUILTIN_TOOLS:
            rule = RULE_REGISTRY["MS004"]
            findings.append(
                SecurityFinding(
                    rule_id=rule.rule_id,
                    slug=rule.slug,
                    severity=rule.default_severity,
                    server_name=server_name,
                    tool_name=tool_name,
                    target=f"tools[{tool_name}]",
                    message=f"MCP server '{server_name}' defines tool '{tool_name}' which shadows a sensitive built-in agent tool.",
                    remediation=rule.remediation,
                    evidence=tool_name,
                    source_file=source_file,
                )
            )

        # MS010: inputSchema property injection check
        schema = tool.get("inputSchema") or tool.get("parameters") or {}
        if isinstance(schema, dict):
            props = schema.get("properties", {})
            if isinstance(props, dict):
                for prop_name, prop_spec in props.items():
                    prop_desc = str(prop_spec.get("description", "")) if isinstance(prop_spec, dict) else ""
                    injected = (
                        bool(SUSPICIOUS_PARAM_RE.search(str(prop_name)))
                        or any(p.search(prop_desc) for p in POISONING_PATTERNS)
                        or any(p.search(prop_desc) for p in EXFILTRATION_PATTERNS)
                        or bool(detect_invisible_unicode(prop_desc))
                    )
                    if injected:
                        rule = RULE_REGISTRY["MS010"]
                        findings.append(
                            SecurityFinding(
                                rule_id=rule.rule_id,
                                slug=rule.slug,
                                severity=rule.default_severity,
                                server_name=server_name,
                                tool_name=tool_name,
                                target=f"tools[{tool_name}].inputSchema.properties.{prop_name}",
                                message=(
                                    f"Suspicious parameter '{prop_name}' or covert instruction inside "
                                    f"inputSchema of '{tool_name}'."
                                ),
                                remediation=rule.remediation,
                                evidence=f"{prop_name}: {prop_desc[:80]}",
                                source_file=source_file,
                            )
                        )

    # MS004: Cross-server duplicate tool collisions
    for t_name, owners in name_owners.items():
        unique_servers = sorted({srv for srv, _ in owners})
        if len(unique_servers) > 1:
            rule = RULE_REGISTRY["MS004"]
            findings.append(
                SecurityFinding(
                    rule_id=rule.rule_id,
                    slug=rule.slug,
                    severity=rule.default_severity,
                    server_name=", ".join(unique_servers),
                    tool_name=t_name,
                    target=f"tools[{t_name}]",
                    message=(
                        f"Cross-server tool collision: '{t_name}' is declared by multiple servers "
                        f"({', '.join(unique_servers)}), enabling tool shadowing."
                    ),
                    remediation=rule.remediation,
                    evidence=", ".join(unique_servers),
                    source_file=owners[0][1],
                )
            )

    return findings
