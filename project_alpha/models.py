"""Data structures for Project Alpha security audit findings."""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Dict, List, Optional


@dataclass
class Finding:
    """Represents a single security finding discovered during an audit."""

    id: str
    title: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str
    url: str
    evidence: str
    remediation: str

    def to_dict(self) -> Dict[str, str]:
        return asdict(self)


@dataclass
class FormInfo:
    """Represents a discovered HTML form surface."""

    page_url: str
    action: str
    method: str
    inputs: List[Dict[str, str]] = field(default_factory=list)


@dataclass
class PageSnapshot:
    """Captured HTTP + DOM snapshot of a crawled page."""

    url: str
    status_code: int
    headers: Dict[str, str]
    cookies: List[str]
    html: str
    links: List[str] = field(default_factory=list)
    forms: List[FormInfo] = field(default_factory=list)
    rendered_via: str = "http"


@dataclass
class ScanReport:
    """Complete structured security audit report."""

    target: str
    mode: str
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: Optional[str] = None
    pages_scanned: int = 0
    forms_discovered: int = 0
    findings: List[Finding] = field(default_factory=list)

    def severity_counts(self) -> Dict[str, int]:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            sev = f.severity.upper()
            if sev in counts:
                counts[sev] += 1
        return counts

    def to_dict(self) -> Dict:
        return {
            "tool": "Project Alpha v1.0.0",
            "author": "Navida Wijesuriya (RC-JESTOR)",
            "target": self.target,
            "mode": self.mode,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "summary": {
                "pages_scanned": self.pages_scanned,
                "forms_discovered": self.forms_discovered,
                "total_findings": len(self.findings),
                "severity_breakdown": self.severity_counts(),
            },
            "findings": [f.to_dict() for f in self.findings],
        }
