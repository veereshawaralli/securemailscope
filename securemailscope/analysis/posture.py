"""Posture scoring: turn a session's findings into a 0-100 score, a letter
grade and a risk label, and roll individual sessions up into a capture-wide
posture (the weakest link is weighted, since one broken session exposes mail).
"""
from __future__ import annotations

from .models import SEVERITY_PENALTY, Severity


def score_session(findings) -> int:
    """Deduct per-finding penalties from a perfect 100, clamped to [0, 100]."""
    score = 100
    for f in findings:
        score -= SEVERITY_PENALTY.get(f.severity, 0)
    return max(0, min(100, score))


def grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def risk_label(findings) -> str:
    top = max((f.severity for f in findings), default=Severity.INFO)
    return {
        Severity.CRITICAL: "critical",
        Severity.HIGH: "high",
        Severity.MEDIUM: "medium",
        Severity.LOW: "low",
        Severity.INFO: "minimal",
    }[top]


def overall(session_scores) -> tuple:
    """Blend the worst session (60%) with the mean (40%) so a single broken
    session dominates without erasing the rest of the picture."""
    if not session_scores:
        return 100, "A"
    worst = min(session_scores)
    mean = sum(session_scores) / len(session_scores)
    blended = round(0.6 * worst + 0.4 * mean)
    blended = max(0, min(100, blended))
    return blended, grade(blended)
