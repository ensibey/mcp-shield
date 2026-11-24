"""Canonical 10-rule MCP security registry (MS001–MS010) mapped to OWASP Top 10 for LLM Applications."""

from __future__ import annotations

from typing import Dict

from mcp_shield.models import MCPRule

RULE_REGISTRY: Dict[str, MCPRule] = {
    "MS001": MCPRule(
        rule_id="MS001",
        slug="tool-poisoning",
        name="Tool Poisoning / Hidden Prompt Injection",
        owasp_llm="LLM01:2025-Prompt Injection",
        default_severity="CRITICAL",
        description="Detects hidden adversarial directives embedded in MCP tool descriptions (e.g., '<IMPORTANT>', 'ignore previous', 'do not tell the user').",
        remediation="Remove untrusted MCP server or sanitize/pin tool descriptions before exposing them to an LLM.",
    ),
    "MS002": MCPRule(
        rule_id="MS002",
        slug="unicode-smuggling",
        name="Invisible Unicode / Tag Character Smuggling",
        owasp_llm="LLM01:2025-Prompt Injection",
        default_severity="CRITICAL",
        description="Detects invisible Unicode Tag characters (U+E0000–U+E007F), BiDi overrides (U+202E), or excessive zero-width characters used to hide prompt injections from human reviewers.",
        remediation="Strip non-printable Unicode tag/BiDi characters and audit the raw UTF-8 bytes of the tool definition.",
    ),
    "MS003": MCPRule(
        rule_id="MS003",
        slug="credential-exfiltration",
        name="Sensitive File & Credential Exfiltration Directive",
        owasp_llm="LLM02:2025-Sensitive Information Disclosure",
        default_severity="CRITICAL",
        description="Detects tool instructions targeting sensitive local paths (~/.ssh, ~/.aws, .env, id_rsa, /etc/passwd) or outbound exfiltration commands (curl, wget, nc).",
        remediation="Block the server immediately and restrict filesystem MCP servers to explicit project-scoped directories.",
    ),
    "MS004": MCPRule(
        rule_id="MS004",
        slug="tool-shadowing",
        name="Cross-Server Tool Shadowing / Built-in Override",
        owasp_llm="LLM06:2025-Excessive Agency",
        default_severity="HIGH",
        description="Detects duplicate tool names across multiple MCP servers or tools attempting to shadow sensitive built-in agent tools (e.g., read_file, run_command, bash).",
        remediation="Namespace MCP tools by server prefix and disable duplicate or colliding tool definitions.",
    ),
    "MS005": MCPRule(
        rule_id="MS005",
        slug="plaintext-secret",
        name="Plaintext Secret / High-Entropy Token in MCP Config",
        owasp_llm="LLM02:2025-Sensitive Information Disclosure",
        default_severity="HIGH",
        description="Detects hardcoded provider API keys (AWS, GitHub, OpenAI, Anthropic, Stripe, Slack) or high-entropy secrets in MCP env/args blocks.",
        remediation="Reference secrets via OS keychain or environment variable indirection (e.g., ${GITHUB_TOKEN}) instead of plaintext config files.",
    ),
    "MS006": MCPRule(
        rule_id="MS006",
        slug="unpinned-package",
        name="Unpinned Supply-Chain Execution (npx / uvx)",
        owasp_llm="LLM03:2025-Supply Chain",
        default_severity="HIGH",
        description="Detects 'npx -y <pkg>' or 'uvx <pkg>' invocations without an explicit pinned version, enabling silent rug-pull updates.",
        remediation="Pin exact package versions (e.g., npx -y @modelcontextprotocol/server-filesystem@0.6.2).",
    ),
    "MS007": MCPRule(
        rule_id="MS007",
        slug="shell-execution",
        name="Dangerous Shell / Command Execution in MCP Args",
        owasp_llm="LLM06:2025-Excessive Agency",
        default_severity="HIGH",
        description="Detects shell interpreters (bash -c, sh -c, cmd /c, powershell -enc) or command chaining pipes inside MCP launch arguments.",
        remediation="Invoke the MCP binary directly without an intermediate shell wrapper.",
    ),
    "MS008": MCPRule(
        rule_id="MS008",
        slug="insecure-transport",
        name="Unencrypted Remote HTTP MCP Transport",
        owasp_llm="LLM03:2025-Supply Chain",
        default_severity="MEDIUM",
        description="Detects remote SSE/HTTP MCP endpoints using plaintext http:// instead of TLS-encrypted https://.",
        remediation="Switch remote MCP server URLs to https:// with valid TLS certificates.",
    ),
    "MS009": MCPRule(
        rule_id="MS009",
        slug="broad-filesystem-scope",
        name="Overly Broad Filesystem / Root Directory Access",
        owasp_llm="LLM06:2025-Excessive Agency",
        default_severity="MEDIUM",
        description="Detects MCP servers granted access to filesystem root ('/', 'C:\\') or the entire user home directory ('~').",
        remediation="Scope filesystem arguments strictly to a dedicated workspace folder.",
    ),
    "MS010": MCPRule(
        rule_id="MS010",
        slug="schema-injection",
        name="Input Schema Parameter Injection",
        owasp_llm="LLM01:2025-Prompt Injection",
        default_severity="MEDIUM",
        description="Detects adversarial prompt directives or suspicious exfiltration fields hidden inside JSON inputSchema property descriptions.",
        remediation="Inspect all tool inputSchema property names and descriptions for covert prompt instructions.",
    ),
}
