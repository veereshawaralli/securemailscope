"""Core data models for the analysis layer: severity levels, findings and the
nested result objects that every report and the dashboard consume. Everything
is plain-dataclass with `to_dict()` so JSON / HTML / PDF share one shape.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name


# points each finding deducts from the 0-100 posture score (see posture.py)
SEVERITY_PENALTY = {
    Severity.INFO: 0,
    Severity.LOW: 4,
    Severity.MEDIUM: 10,
    Severity.HIGH: 22,
    Severity.CRITICAL: 38,
}


@dataclass
class Finding:
    id: str
    title: str
    severity: Severity
    category: str
    evidence: str
    recommendation: str
    refs: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.label,
            "severity_level": int(self.severity),
            "category": self.category,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "refs": list(self.refs),
        }


@dataclass
class SessionResult:
    """One analyzed TLS/email session: flattened summary, certs, findings,
    the ML feature vector and the derived score / risk labels."""
    stream: str
    protocol: str
    server_port: int
    summary: dict = field(default_factory=dict)       # tls + email flat facts
    certificates: list = field(default_factory=list)  # list[CertInfo dict]
    findings: list = field(default_factory=list)       # list[Finding]
    features: dict = field(default_factory=dict)
    score: int = 100
    grade: str = "A"
    risk_label: str = "low"
    anomaly: bool = False
    anomaly_score: float = 0.0

    def counts(self) -> dict:
        c = {s.label: 0 for s in Severity}
        for f in self.findings:
            c[f.severity.label] += 1
        return c

    def to_dict(self) -> dict:
        return {
            "stream": self.stream,
            "protocol": self.protocol,
            "server_port": self.server_port,
            "summary": self.summary,
            "certificates": self.certificates,
            "findings": [f.to_dict() for f in self.findings],
            "features": self.features,
            "score": self.score,
            "grade": self.grade,
            "risk_label": self.risk_label,
            "anomaly": self.anomaly,
            "anomaly_score": round(self.anomaly_score, 4),
            "severity_counts": self.counts(),
        }


@dataclass
class AnalysisResult:
    """Whole-capture result: every session plus the rolled-up posture."""
    source: str
    generated_at: str = ""
    tool_version: str = ""
    sessions: list = field(default_factory=list)       # list[SessionResult]
    overall_score: int = 100
    overall_grade: str = "A"

    def severity_totals(self) -> dict:
        tot = {s.label: 0 for s in Severity}
        for sess in self.sessions:
            for k, v in sess.counts().items():
                tot[k] += v
        return tot

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "generated_at": self.generated_at,
            "tool_version": self.tool_version,
            "session_count": len(self.sessions),
            "overall_score": self.overall_score,
            "overall_grade": self.overall_grade,
            "severity_totals": self.severity_totals(),
            "sessions": [s.to_dict() for s in self.sessions],
        }


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
