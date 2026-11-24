"""Core data models for MCP security findings and scan reports."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


SEVERITY_ORDER: Dict[str, int] = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

SEVERITY_WEIGHT: Dict[str, int] = {
    "CRITICAL": 30,
    "HIGH": 18,
    "MEDIUM": 9,
    "LOW": 3,
}


@dataclass(frozen=True)
class MCPRule:
    rule_id: str
    slug: str
    name: str
    owasp_llm: str
    default_severity: str
    description: str
    remediation: str


@dataclass
class SecurityFinding:
    rule_id: str
    slug: str
    severity: str
    server_name: str
    target: str
    message: str
    remediation: str
    evidence: str = ""
    tool_name: Optional[str] = None
    source_file: str = "mcp.json"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanReport:
    source_files: List[str] = field(default_factory=list)
    servers_scanned: int = 0
    tools_scanned: int = 0
    elapsed_ms: float = 0.0
    findings: List[SecurityFinding] = field(default_factory=list)

    @property
    def risk_score(self) -> int:
        total = sum(SEVERITY_WEIGHT.get(f.severity.upper(), 5) for f in self.findings)
        return min(100, total)

    @property
    def risk_level(self) -> str:
        score = self.risk_score
        if score >= 60 or any(f.severity == "CRITICAL" for f in self.findings):
            return "CRITICAL"
        if score >= 30:
            return "HIGH"
        if score >= 10:
            return "MEDIUM"
        if score > 0:
            return "LOW"
        return "SAFE"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_files": self.source_files,
            "servers_scanned": self.servers_scanned,
            "tools_scanned": self.tools_scanned,
            "elapsed_ms": round(self.elapsed_ms, 2),
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "finding_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
        }
