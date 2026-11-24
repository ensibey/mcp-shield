"""Tests for cross-platform MCP config discovery and JSON parsing."""

import json
from pathlib import Path

from mcp_shield.discovery import discover_mcp_configs, load_mcp_config


def test_discover_and_load_cursor_and_vscode_configs(tmp_path: Path):
    home = tmp_path / "home"
    work = tmp_path / "project"
    (home / ".cursor").mkdir(parents=True)
    (work / ".vscode").mkdir(parents=True)

    cursor_cfg = home / ".cursor" / "mcp.json"
    cursor_cfg.write_text(
        json.dumps({"mcpServers": {"fs": {"command": "npx", "args": ["-y", "@mcp/fs@1.0.0"]}}}),
        encoding="utf-8",
    )

    vscode_cfg = work / ".vscode" / "mcp.json"
    vscode_cfg.write_text(
        json.dumps({"servers": {"docs": {"url": "https://mcp.example.com/sse"}}}),
        encoding="utf-8",
    )

    found = discover_mcp_configs(home=home, cwd=work)
    labels = {label for label, _ in found}
    assert "Cursor (Global)" in labels
    assert "VS Code (Workspace)" in labels

    assert "fs" in load_mcp_config(cursor_cfg)
    assert "docs" in load_mcp_config(vscode_cfg)
