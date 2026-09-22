"""JSON report writer. Serializes an AnalysisResult (plus the prioritized
recommendation list) into a single machine-readable document — the canonical
format other tools, CI gates or the dashboard can consume.
"""
from __future__ import annotations

import json

from ..analysis.engine import full_dict


def render(result) -> str:
    """Return the full analysis as a pretty-printed JSON string."""
    return json.dumps(full_dict(result), indent=2, sort_keys=False,
                      default=str)


def write(result, path: str) -> str:
    """Write the JSON report to `path`; return the path."""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render(result))
    return path
