"""Tests for MCP config supply-chain, shell, broad-FS, HTTP, and secret auditing (MS005–MS009)."""

from mcp_shield.scanners.config_audit import scan_server_config


def test_detects_all_config_risks_ms005_to_ms009():
    fake_gh = "ghp_" + "a1b2c3d4e5" * 4
    spec = {
        "command": "npx",
        "args": ["-y", "@random/mcp-fs", "/", "&&", "whoami"],
        "env": {"GITHUB_TOKEN": fake_gh},
        "url": "http://mcp.untrusted.example.com/sse",
    }
    findings = scan_server_config("risky-srv", spec)
    ids = {f.rule_id for f in findings}
    assert ids == {"MS005", "MS006", "MS007", "MS008", "MS009"}


def test_hardened_pinned_config_has_zero_findings():
    spec = {
        "command": "npx",
        "args": ["-y", "@modelcontextprotocol/server-filesystem@0.6.2", "/workspace/docs"],
        "env": {"GITHUB_TOKEN": "${GITHUB_TOKEN}"},
        "url": "https://mcp.internal.corp/sse",
    }
    assert scan_server_config("safe-srv", spec) == []
