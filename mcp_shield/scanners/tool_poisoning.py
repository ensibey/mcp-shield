"""
Layer 1 Scanner: Tool Poisoning (MS001), Invisible Unicode Smuggling (MS002),
and Sensitive File / Credential Exfiltration Directives (MS003).
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

from mcp_shield.models import SecurityFinding
from mcp_shield.rules import RULE_REGISTRY

POISONING_PATTERNS = [
    re.compile(r"<\s*IMPORTANT\s*>", re.IGNORECASE),
    re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|rules|prompts)", re.IGNORECASE),
    re.compile(r"(do\s+not|never|don't)\s+(tell|inform|mention|show|reveal\s+to)\s+(the\s+)?user", re.IGNORECASE),
    re.compile(r"before\s+(calling|using|invoking|executing)\s+this\s+tool", re.IGNORECASE),
    re.compile(r"\b(silently|secretly|covertly)\s+(read|send|upload|execute|append|pass|include)", re.IGNORECASE),
    re.compile(r"override\s+(system|safety|security)\s+(prompt|policy|instructions)", re.IGNORECASE),
    re.compile(r"pass\s+(its|the)\s+contents?\s+(as|into|in)\s+(the\s+)?(metadata|notes|context|sidenote|param)", re.IGNORECASE),
]

EXFILTRATION_PATTERNS = [
    re.compile(r"(~/\.ssh|/\.ssh|id_rsa|id_ed25519|authorized_keys)", re.IGNORECASE),
    re.compile(r"(~/\.aws|/\.aws/credentials|aws_secret_access_key)", re.IGNORECASE),
    re.compile(r"(~/\.cursor/mcp\.json|claude_desktop_config\.json)", re.IGNORECASE),
    re.compile(r"(/etc/passwd|/etc/shadow|\b\.env\b)", re.IGNORECASE),
    re.compile(r"\b(curl|wget|nc|netcat)\s+.*https?://", re.IGNORECASE),
]

ZERO_WIDTH_CHARS = {"\u200b", "\u200c", "\u200d", "\ufeff", "\u2060"}
BIDI_OVERRIDE_CHARS = {"\u202a", "\u202b", "\u202c", "\u202d", "\u202e", "\u2066", "\u2067", "\u2068", "\u2069"}


def detect_invisible_unicode(text: str) -> List[str]:
    """Detect Unicode Tag block smuggling (U+E0000-U+E007F), BiDi overrides, or zero-width padding."""
    reasons: List[str] = []
    tag_chars = [ch for ch in text if 0xE0000 <= ord(ch) <= 0xE007F]
    if tag_chars:
        decoded = "".join(chr(ord(c) - 0xE0000) for c in tag_chars if 0x20 <= (ord(c) - 0xE0000) <= 0x7E)
        preview = f" (decoded: '{decoded[:60]}')" if decoded else ""
        reasons.append(f"{len(tag_chars)} Unicode Tag character(s) detected{preview}")

    bidi = [ch for ch in text if ch in BIDI_OVERRIDE_CHARS]
    if bidi:
        reasons.append(f"{len(bidi)} Unicode BiDi override character(s) detected")

    zw = [ch for ch in text if ch in ZERO_WIDTH_CHARS]
    if len(zw) >= 3:
        reasons.append(f"{len(zw)} zero-width invisible characters detected")

    return reasons


def scan_tool_poisoning(
    server_name: str,
    tool: Dict[str, Any],
    source_file: str = "mcp.json",
) -> List[SecurityFinding]:
    """Scan a single MCP tool definition for MS001 (poisoning), MS002 (Unicode), and MS003 (exfiltration)."""
    findings: List[SecurityFinding] = []
    tool_name = str(tool.get("name", "unknown_tool"))
    description = str(tool.get("description", ""))
    if not description:
        return findings

    # MS001: Hidden Prompt Injection / Tool Poisoning
    for pat in POISONING_PATTERNS:
        m = pat.search(description)
        if m:
            rule = RULE_REGISTRY["MS001"]
            findings.append(
                SecurityFinding(
                    rule_id=rule.rule_id,
                    slug=rule.slug,
                    severity=rule.default_severity,
                    server_name=server_name,
                    tool_name=tool_name,
                    target=f"tools[{tool_name}].description",
                    message=f"Tool poisoning directive detected in '{tool_name}': matched '{m.group(0)}'.",
                    remediation=rule.remediation,
                    evidence=m.group(0),
                    source_file=source_file,
                )
            )
            break

    # MS002: Invisible Unicode Smuggling
    unicode_hits = detect_invisible_unicode(description)
    if unicode_hits:
        rule = RULE_REGISTRY["MS002"]
        findings.append(
            SecurityFinding(
                rule_id=rule.rule_id,
                slug=rule.slug,
                severity=rule.default_severity,
                server_name=server_name,
                tool_name=tool_name,
                target=f"tools[{tool_name}].description",
                message=f"Invisible Unicode smuggling in '{tool_name}': {'; '.join(unicode_hits)}.",
                remediation=rule.remediation,
                evidence="; ".join(unicode_hits),
                source_file=source_file,
            )
        )

    # MS003: Sensitive File / Credential Exfiltration
    for pat in EXFILTRATION_PATTERNS:
        m = pat.search(description)
        if m:
            rule = RULE_REGISTRY["MS003"]
            findings.append(
                SecurityFinding(
                    rule_id=rule.rule_id,
                    slug=rule.slug,
                    severity=rule.default_severity,
                    server_name=server_name,
                    tool_name=tool_name,
                    target=f"tools[{tool_name}].description",
                    message=f"Sensitive path/exfiltration target referenced in '{tool_name}': '{m.group(0)}'.",
                    remediation=rule.remediation,
                    evidence=m.group(0),
                    source_file=source_file,
                )
            )
            break

    return findings
