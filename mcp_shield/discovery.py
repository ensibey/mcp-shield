"""
Cross-platform MCP client configuration auto-discovery and JSON parser.

Discovers MCP server configurations for Cursor, Claude Desktop, Windsurf,
VS Code, and project-local `mcp.json` across Windows, macOS, and Linux.
"""

from __future__ import annotations

import json
import os
import platform
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def candidate_config_paths(home: Optional[Path] = None, cwd: Optional[Path] = None) -> List[Tuple[str, Path]]:
    """Return known (client_label, path) locations for MCP configuration files."""
    h = (home or Path.home()).resolve()
    work = (cwd or Path.cwd()).resolve()
    sys_name = platform.system().lower()

    paths: List[Tuple[str, Path]] = [
        ("Cursor (Global)", h / ".cursor" / "mcp.json"),
        ("Cursor (Workspace)", work / ".cursor" / "mcp.json"),
        ("Windsurf", h / ".codeium" / "windsurf" / "mcp_config.json"),
        ("VS Code (Workspace)", work / ".vscode" / "mcp.json"),
        ("Local mcp.json", work / "mcp.json"),
    ]

    if sys_name == "windows":
        appdata = Path(os.environ.get("APPDATA", str(h / "AppData" / "Roaming")))
        paths.append(("Claude Desktop", appdata / "Claude" / "claude_desktop_config.json"))
        paths.append(("VS Code (User)", appdata / "Code" / "User" / "mcp.json"))
    elif sys_name == "darwin":
        app_sup = h / "Library" / "Application Support"
        paths.append(("Claude Desktop", app_sup / "Claude" / "claude_desktop_config.json"))
        paths.append(("VS Code (User)", app_sup / "Code" / "User" / "mcp.json"))
    else:
        xdg = Path(os.environ.get("XDG_CONFIG_HOME", str(h / ".config")))
        paths.append(("Claude Desktop", xdg / "Claude" / "claude_desktop_config.json"))
        paths.append(("VS Code (User)", xdg / "Code" / "User" / "mcp.json"))

    return paths


def discover_mcp_configs(home: Optional[Path] = None, cwd: Optional[Path] = None) -> List[Tuple[str, Path]]:
    """Return existing MCP config files found on the current machine."""
    seen = set()
    found: List[Tuple[str, Path]] = []
    for label, p in candidate_config_paths(home=home, cwd=cwd):
        if p.is_file():
            key = str(p.resolve()).lower()
            if key not in seen:
                seen.add(key)
                found.append((label, p))
    return found


def load_mcp_config(path: Path) -> Dict[str, Dict[str, Any]]:
    """
    Parse an MCP JSON config file into a normalized `{server_name: server_spec}` map.
    Supports standard `mcpServers`, VS Code `servers`, and flat server dictionaries.
    """
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        return {}

    for key in ("mcpServers", "servers"):
        section = raw.get(key)
        if isinstance(section, dict):
            return {str(k): v for k, v in section.items() if isinstance(v, dict)}

    # Fallback: if root values look like server specs (have command or url)
    if any(isinstance(v, dict) and ("command" in v or "url" in v or "tools" in v) for v in raw.values()):
        return {str(k): v for k, v in raw.items() if isinstance(v, dict)}

    return {}
