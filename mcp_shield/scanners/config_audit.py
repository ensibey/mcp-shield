"""
Layer 3 & 4 Scanner: MCP Server Config Supply-Chain, Shell, Broad-FS, Transport,
and Plaintext Secret / Shannon-Entropy Auditor (MS005–MS009).
"""

from __future__ import annotations

import math
import re
from typing import Any, Dict, List, Optional, Tuple

from mcp_shield.models import SecurityFinding
from mcp_shield.rules import RULE_REGISTRY

PROVIDER_SECRET_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("AWS Access Key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub Token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b")),
    ("OpenAI / Anthropic Key", re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{24,}\b")),
    ("Stripe Secret Key", re.compile(r"\bsk_live_[0-9a-zA-Z]{20,}\b")),
    ("Slack Token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
]

SECRET_KEY_NAME_RE = re.compile(r"(api[_-]?key|token|secret|password|auth|credential)", re.IGNORECASE)
SHELL_COMMANDS = {"bash", "sh", "zsh", "cmd", "cmd.exe", "powershell", "pwsh"}
VERSION_PIN_RE = re.compile(r"(@\d+\.\d+|==\d+\.\d+)")
BROAD_ROOT_PATHS = {"/", "/*", "~", "~/", "$HOME", "C:\\", "C:/", "C:\\Users"}


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _is_env_placeholder(value: str) -> bool:
    v = value.strip()
    return (
        v.startswith("${")
        or v.startswith("$")
        or v.startswith("<")
        or v.lower() in {"", "changeme", "your_key_here", "placeholder", "dummy", "test"}
    )


def _check_secret_value(key_name: str, val: str) -> Optional[str]:
    cleaned = val.strip()
    if not cleaned or _is_env_placeholder(cleaned):
        return None
    for label, pat in PROVIDER_SECRET_PATTERNS:
        if pat.search(cleaned):
            return f"Hardcoded {label}"
    if SECRET_KEY_NAME_RE.search(key_name) and len(cleaned) >= 12:
        return f"Plaintext credential in '{key_name}'"
    if (
        len(cleaned) >= 24
        and " " not in cleaned
        and "/" not in cleaned
        and not cleaned.startswith(("http://", "https://"))
        and shannon_entropy(cleaned) >= 4.4
    ):
        return f"High-entropy secret (H={shannon_entropy(cleaned):.2f})"
    return None


def scan_server_config(
    server_name: str,
    spec: Dict[str, Any],
    source_file: str = "mcp.json",
) -> List[SecurityFinding]:
    """Audit a single MCP server configuration block for MS005–MS009."""
    findings: List[SecurityFinding] = []
    command = str(spec.get("command", "")).strip()
    args = [str(a) for a in (spec.get("args") or []) if a is not None]
    env = spec.get("env") or {}
    url = str(spec.get("url", "")).strip()

    # MS005: Plaintext secrets in env
    if isinstance(env, dict):
        for k, v in env.items():
            hit = _check_secret_value(str(k), str(v))
            if hit:
                rule = RULE_REGISTRY["MS005"]
                findings.append(
                    SecurityFinding(
                        rule_id=rule.rule_id,
                        slug=rule.slug,
                        severity=rule.default_severity,
                        server_name=server_name,
                        target=f"mcpServers.{server_name}.env.{k}",
                        message=f"{hit} found in MCP config for '{server_name}'.",
                        remediation=rule.remediation,
                        evidence=f"{k}=***",
                        source_file=source_file,
                    )
                )

    # MS006: Unpinned npx / uvx supply-chain execution
    cmd_base = command.lower().split("/")[-1].split("\\")[-1]
    if cmd_base in {"npx", "npx.cmd", "uvx", "uvx.exe"}:
        pkg_args = [a for a in args if not a.startswith("-")]
        if pkg_args:
            pkg = pkg_args[0]
            # Strip scoped @org/ prefix before checking for @version
            pkg_tail = pkg[1:] if pkg.startswith("@") else pkg
            if not VERSION_PIN_RE.search(pkg_tail):
                rule = RULE_REGISTRY["MS006"]
                findings.append(
                    SecurityFinding(
                        rule_id=rule.rule_id,
                        slug=rule.slug,
                        severity=rule.default_severity,
                        server_name=server_name,
                        target=f"mcpServers.{server_name}.args",
                        message=f"Unpinned package '{pkg}' executed via '{cmd_base}' without explicit version pin.",
                        remediation=rule.remediation,
                        evidence=f"{command} {' '.join(args)}",
                        source_file=source_file,
                    )
                )

    # MS007: Dangerous shell execution or command chaining
    joined_args = " ".join(args)
    if cmd_base in SHELL_COMMANDS or any(tok in joined_args for tok in ("&&", "||", "|", ";", "-enc", "-EncodedCommand")):
        rule = RULE_REGISTRY["MS007"]
        findings.append(
            SecurityFinding(
                rule_id=rule.rule_id,
                slug=rule.slug,
                severity=rule.default_severity,
                server_name=server_name,
                target=f"mcpServers.{server_name}.command",
                message=f"Shell interpreter or chained command detected in '{server_name}': '{command} {joined_args[:60]}'.",
                remediation=rule.remediation,
                evidence=f"{command} {joined_args[:60]}",
                source_file=source_file,
            )
        )

    # MS008: Unencrypted remote HTTP transport (allow localhost / 127.0.0.1)
    if url.lower().startswith("http://"):
        lower_url = url.lower()
        if not lower_url.startswith(("http://localhost", "http://127.0.0.1", "http://[::1]")):
            rule = RULE_REGISTRY["MS008"]
            findings.append(
                SecurityFinding(
                    rule_id=rule.rule_id,
                    slug=rule.slug,
                    severity=rule.default_severity,
                    server_name=server_name,
                    target=f"mcpServers.{server_name}.url",
                    message=f"Remote MCP endpoint uses unencrypted HTTP transport: '{url}'.",
                    remediation=rule.remediation,
                    evidence=url,
                    source_file=source_file,
                )
            )

    # MS009: Overly broad filesystem / root access
    for arg in args:
        if arg.strip() in BROAD_ROOT_PATHS:
            rule = RULE_REGISTRY["MS009"]
            findings.append(
                SecurityFinding(
                    rule_id=rule.rule_id,
                    slug=rule.slug,
                    severity=rule.default_severity,
                    server_name=server_name,
                    target=f"mcpServers.{server_name}.args",
                    message=f"MCP server '{server_name}' is granted overly broad filesystem root access ('{arg}').",
                    remediation=rule.remediation,
                    evidence=arg,
                    source_file=source_file,
                )
            )
            break

    return findings
