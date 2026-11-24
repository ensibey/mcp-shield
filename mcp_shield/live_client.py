"""
Sandboxed JSON-RPC 2.0 stdio MCP handshake client.

Performs the official MCP `initialize` + `tools/list` handshake against a local
stdio server with a strict timeout so `mcp-shield` can audit live tool schemas.
"""

from __future__ import annotations

import json
import os
import subprocess
from typing import Any, Dict, List, Optional


def probe_stdio_mcp_tools(
    command: str,
    args: Optional[List[str]] = None,
    env: Optional[Dict[str, str]] = None,
    timeout_sec: float = 5.0,
) -> List[Dict[str, Any]]:
    """Spawn a stdio MCP server, execute initialize + tools/list, and return declared tools."""
    proc_env = dict(os.environ)
    if env:
        proc_env.update({str(k): str(v) for k, v in env.items()})

    init_req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "mcp-shield", "version": "0.1.0"},
        },
    }
    initialized_notif = {"jsonrpc": "2.0", "method": "notifications/initialized"}
    list_req = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}

    payload = (
        json.dumps(init_req)
        + "\n"
        + json.dumps(initialized_notif)
        + "\n"
        + json.dumps(list_req)
        + "\n"
    )

    try:
        completed = subprocess.run(
            [command, *(args or [])],
            input=payload,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            env=proc_env,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []

    tools: List[Dict[str, Any]] = []
    for line in (completed.stdout or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if msg.get("id") == 2 and isinstance(msg.get("result"), dict):
            raw_tools = msg["result"].get("tools", [])
            if isinstance(raw_tools, list):
                tools.extend(t for t in raw_tools if isinstance(t, dict))
    return tools
