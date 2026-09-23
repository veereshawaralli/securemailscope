"""PDF report writer (reportlab). Produces a printable executive summary: the
overall posture, severity totals, prioritized recommendations and a per-session
breakdown with findings. reportlab is optional — if it is not installed `write`
raises a clear error so the CLI can fall back to the JSON / HTML reports.
"""
from __future__ import annotations

from .json_report import full_dict  # re-exported convenience

try:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (HRFlowable, Paragraph, SimpleDocTemplate,
                                    Spacer, Table, TableStyle)
    _HAVE_RL = True
except Exception:                # pragma: no cover
    _HAVE_RL = False

_SEV_COLOR = {"CRITICAL": "#c9252d", "HIGH": "#d9741f", "MEDIUM": "#b58a00",
              "LOW": "#2f8f57", "INFO": "#5560c0"}
_GRADE_COLOR = {"A": "#2f9e44", "B": "#0f9488", "C": "#b58a00",
                "D": "#d9741f", "F": "#c9252d"}


def _styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle("H", parent=ss["Heading2"], fontSize=13,
                          spaceBefore=12, spaceAfter=6, textColor="#11151c"))
    ss.add(ParagraphStyle("Small", parent=ss["Normal"], fontSize=8,
                          textColor="#5b6672", leading=11))
    ss.add(ParagraphStyle("Cell", parent=ss["Normal"], fontSize=8, leading=11))
    ss.add(ParagraphStyle("CellW", parent=ss["Normal"], fontSize=9, leading=12,
                          textColor=colors.white, alignment=TA_LEFT))
    return ss


def _esc(s) -> str:
    return (str("" if s is None else s).replace("&", "&amp;")
            .replace("<", "&lt;").replace(">", "&gt;"))
def _header(d, ss):
    out = [Paragraph("SecureMailScope &mdash; Cryptographic Posture Report",
                     ss["Title"]),
           Paragraph(f'Source: {_esc(d["source"])} &nbsp;|&nbsp; Sessions: '
                     f'{d["session_count"]} &nbsp;|&nbsp; Tool v'
                     f'{_esc(d["tool_version"])} &nbsp;|&nbsp; '
                     f'{_esc(d["generated_at"])}', ss["Small"]),
           HRFlowable(width="100%", thickness=0.6, color=colors.HexColor("#d0d6de")),
           Spacer(1, 8)]
    gc = _GRADE_COLOR.get(d["overall_grade"], "#5b6672")
    gcell = Paragraph(f'<b>Grade {d["overall_grade"]}</b><br/>'
                      f'{d["overall_score"]} / 100', ss["CellW"])
    gtab = Table([[gcell]], colWidths=[60 * mm])
    gtab.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(gc)),
        ("LEFTPADDING", (0, 0), (-1, -1), 12), ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10)]))
    tot, order = d["severity_totals"], ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    hdr = [Paragraph(f'<b>{s}</b>', ss["CellW"]) for s in order]
    vals = [Paragraph(str(tot.get(s, 0)), ss["Cell"]) for s in order]
    sty = [("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d6de")),
           ("ALIGN", (0, 0), (-1, -1), "CENTER"), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
           ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]
    for i, s in enumerate(order):
        sty.append(("BACKGROUND", (i, 0), (i, 0), colors.HexColor(_SEV_COLOR[s])))
    stab = Table([hdr, vals], colWidths=[26 * mm] * 5)
    stab.setStyle(TableStyle(sty))
    both = Table([[gtab, stab]], colWidths=[64 * mm, 126 * mm])
    both.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
    out += [both, Spacer(1, 10)]
    return out
def _recs(d, ss):
    out = [Paragraph("Prioritized recommendations", ss["H"])]
    recs = d.get("recommendations", [])
    if not recs:
        out.append(Paragraph("No remediation required &mdash; posture is clean.",
                             ss["Small"]))
        return out
    rows = [[Paragraph("<b>#</b>", ss["Cell"]), Paragraph("<b>Sev</b>", ss["Cell"]),
             Paragraph("<b>Recommendation</b>", ss["Cell"]),
             Paragraph("<b>Streams</b>", ss["Cell"])]]
    sty = [("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d6de")),
           ("VALIGN", (0, 0), (-1, -1), "TOP"), ("TOPPADDING", (0, 0), (-1, -1), 4),
           ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
           ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef1f5"))]
    for i, r in enumerate(recs, 1):
        sev = r["severity"]
        sty.append(("TEXTCOLOR", (1, i), (1, i),
                    colors.HexColor(_SEV_COLOR.get(sev, "#333333"))))
        rows.append([Paragraph(str(i), ss["Cell"]),
                     Paragraph(f"<b>{sev}</b>", ss["Cell"]),
                     Paragraph(_esc(r["recommendation"]), ss["Cell"]),
                     Paragraph(str(r.get("affected_streams", 0)), ss["Cell"])])
    t = Table(rows, colWidths=[8 * mm, 22 * mm, 140 * mm, 20 * mm])
    t.setStyle(TableStyle(sty))
    out.append(t)
    return out
def _kv(su, s, ss):
    tls = su.get("negotiated_version_name") or (
        "TLS (unparsed)" if su.get("tls_present") else "no TLS")
    pairs = [
        ("Stream", s["stream"]),
        ("Protocol / port", f'{s["protocol"]} : {s["server_port"]}'),
        ("TLS version", tls),
        ("Cipher suite", f'{su.get("cipher_suite_name") or "—"} '
                         f'(grade {su.get("cipher_grade")}, {su.get("cipher_bits", 0)}b)'),
        ("PFS / AEAD", f'{"yes" if su.get("cipher_pfs") else "no"} / '
                       f'{"yes" if su.get("cipher_aead") else "no"}'),
        ("STARTTLS", f'offered {"yes" if su.get("starttls_offered") else "no"}, '
                     f'used {"yes" if su.get("starttls_used") else "no"}'),
        ("Cleartext auth", "YES (credentials exposed)"
                           if su.get("cleartext_auth") else "no"),
        ("Risk / ML", f'{s["risk_label"]} / {su.get("ml_risk", "—")}'),
    ]
    rows = [[Paragraph(f"<b>{k}</b>", ss["Cell"]), Paragraph(_esc(v), ss["Cell"])]
            for k, v in pairs]
    t = Table(rows, colWidths=[40 * mm, 150 * mm])
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#e0e4ea")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"), ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f4f6f9"))]))
    return t


def _findings_tab(findings, ss):
    if not findings:
        return Paragraph("No findings.", ss["Small"])
    rows = [[Paragraph("<b>Sev</b>", ss["Cell"]), Paragraph("<b>ID</b>", ss["Cell"]),
             Paragraph("<b>Finding &amp; recommendation</b>", ss["Cell"])]]
    sty = [("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#e0e4ea")),
           ("VALIGN", (0, 0), (-1, -1), "TOP"), ("TOPPADDING", (0, 0), (-1, -1), 3),
           ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
           ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef1f5"))]
    for i, f in enumerate(findings, 1):
        sty.append(("TEXTCOLOR", (0, i), (0, i),
                    colors.HexColor(_SEV_COLOR.get(f["severity"], "#333333"))))
        body = (f'<b>{_esc(f["title"])}</b><br/>{_esc(f["evidence"])}<br/>'
                f'<i>&rarr; {_esc(f["recommendation"])}</i>')
        rows.append([Paragraph(f'<b>{f["severity"]}</b>', ss["Cell"]),
                     Paragraph(_esc(f["id"]), ss["Cell"]),
                     Paragraph(body, ss["Cell"])])
    t = Table(rows, colWidths=[20 * mm, 34 * mm, 136 * mm])
    t.setStyle(TableStyle(sty))
    return t
def _sessions(d, ss):
    out = [Paragraph("Sessions", ss["H"])]
    for s in d["sessions"]:
        su = s.get("summary", {})
        gc = _GRADE_COLOR.get(s["grade"], "#5b6672")
        band = Table([[Paragraph(
            f'<b>{s["grade"]}</b> &nbsp; <b>{_esc(s["protocol"])}:{s["server_port"]}</b>'
            f' &mdash; score {s["score"]}/100 &middot; risk {_esc(s["risk_label"])}',
            ss["CellW"])]], colWidths=[190 * mm])
        band.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(gc)),
            ("LEFTPADDING", (0, 0), (-1, -1), 8), ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]))
        out += [Spacer(1, 10), band, Spacer(1, 4), _kv(su, s, ss)]
        cert = (s.get("certificates") or [None])[0]
        if cert and cert.get("parsed"):
            out.append(Paragraph(
                f'Certificate: {_esc(cert.get("subject"))} &middot; key '
                f'{_esc(cert.get("public_key_algo"))} {cert.get("key_bits", "")} '
                f'&middot; sig {_esc(cert.get("sig_hash"))} &middot; '
                f'{"EXPIRED" if cert.get("is_expired") else "valid"}', ss["Small"]))
        out += [Spacer(1, 4), _findings_tab(s["findings"], ss)]
    return out


def write(result, path: str) -> str:
    """Build the PDF report at `path`; return the path. Requires reportlab."""
    if not _HAVE_RL:
        raise RuntimeError("reportlab is not installed; run `pip install reportlab` "
                           "or use the JSON / HTML report instead")
    d = full_dict(result)
    ss = _styles()
    story = _header(d, ss) + _recs(d, ss) + _sessions(d, ss)
    doc = SimpleDocTemplate(path, pagesize=A4, topMargin=16 * mm,
                            bottomMargin=16 * mm, leftMargin=12 * mm,
                            rightMargin=12 * mm, title="SecureMailScope Report")
    doc.build(story)
    return path
