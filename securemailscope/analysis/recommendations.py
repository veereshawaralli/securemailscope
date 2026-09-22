"""Aggregate the findings across a capture into a de-duplicated, priority-ordered
remediation list — the "what to fix first" view for the report and dashboard.
"""
from __future__ import annotations

from .models import Severity


def collect(sessions) -> list:
    """Merge findings from every SessionResult into unique recommendations,
    most severe first, each carrying the finding ids and streams it came from."""
    merged: dict = {}
    for sess in sessions:
        for f in sess.findings:
            if f.severity == Severity.INFO:
                continue
            key = f.recommendation.strip()
            if not key:
                continue
            entry = merged.get(key)
            if entry is None:
                entry = merged[key] = {
                    "recommendation": key,
                    "severity": f.severity,
                    "finding_ids": set(),
                    "streams": set(),
                    "refs": set(),
                }
            entry["severity"] = max(entry["severity"], f.severity)
            entry["finding_ids"].add(f.id)
            entry["streams"].add(sess.stream)
            entry["refs"].update(f.refs)

    out = []
    for e in merged.values():
        out.append({
            "recommendation": e["recommendation"],
            "severity": e["severity"].label,
            "severity_level": int(e["severity"]),
            "finding_ids": sorted(e["finding_ids"]),
            "affected_streams": sorted(e["streams"]),
            "refs": sorted(e["refs"]),
        })
    out.sort(key=lambda r: (-r["severity_level"], r["recommendation"]))
    return out
