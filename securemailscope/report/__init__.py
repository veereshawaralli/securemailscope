"""Forensic report generation: JSON, HTML (standalone dashboard) and PDF.

Each writer exposes ``write(result, path) -> path``; JSON and HTML also expose
``render(result) -> str``. PDF requires the optional ``reportlab`` package.
"""
from . import html_report, json_report

import os

__all__ = ["json_report", "html_report", "write"]


def write(result, path: str, fmt: str = "json") -> str:
    """Dispatch to the writer for `fmt` in {json, html, pdf}."""
    fmt = fmt.lower()
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    if fmt == "json":
        return json_report.write(result, path)
    if fmt == "html":
        return html_report.write(result, path)
    if fmt == "pdf":
        from . import pdf_report          # imported lazily (optional reportlab)
        return pdf_report.write(result, path)
    raise ValueError(f"unknown report format: {fmt!r} (use json, html or pdf)")
