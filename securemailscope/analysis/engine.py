"""End-to-end analysis pipeline: PCAP -> reassembled TCP streams -> email/TLS
dissection -> certificate analysis -> rules + posture + optional ML -> a single
AnalysisResult. This is the one entry point the CLI, reports and dashboard call.
"""
from __future__ import annotations

import dataclasses

from ..certs.analyze import analyze_chain
from ..pcapio.reader import reassemble
from ..protocols import email_detect
from ..tls import cipher_suites
from ..tls import constants as C
from ..tls import handshake as hs
from ..tls.records import iter_handshakes, iter_records
from . import features, posture, recommendations, rules
from .models import AnalysisResult, SessionResult, now_iso

try:
    from ..version import __version__ as VERSION
except Exception:            # pragma: no cover
    VERSION = "0.0.0"

_EMAIL_PORTS = {25, 465, 587, 143, 993, 110, 995}


def _extract_handshakes(client_tls: bytes, server_tls: bytes) -> dict:
    """Pull ClientHello / ServerHello / Certificate out of the TLS byte ranges."""
    ch = sh = None
    for m in iter_handshakes(iter_records(client_tls)):
        if m.msg_type == C.HS_CLIENT_HELLO:
            try:
                ch = hs.parse_client_hello(m.body)
            except Exception:
                ch = None
            break
    server_msgs = list(iter_handshakes(iter_records(server_tls)))
    for m in server_msgs:
        if m.msg_type == C.HS_SERVER_HELLO:
            try:
                sh = hs.parse_server_hello(m.body)
            except Exception:
                sh = None
            break
    negotiated = sh.get("negotiated_version") if sh else None
    tls13 = negotiated == C.TLS_1_3
    certs: list = []
    for m in server_msgs:                 # Certificate is cleartext only <= TLS 1.2
        if m.msg_type == C.HS_CERTIFICATE:
            try:
                certs = hs.parse_certificate(m.body, tls13=tls13)
            except Exception:
                certs = []
            if certs:
                break
    return {"client_hello": ch, "server_hello": sh, "certs": certs}


def _build_summary(email, hsx: dict) -> dict:
    """Flatten email + TLS facts into the dict rules/features/reports consume."""
    ch, sh = hsx["client_hello"], hsx["server_hello"]
    negotiated = sh.get("negotiated_version") if sh else None
    suite_code = sh.get("cipher_suite") if sh else None
    cs = cipher_suites.lookup(suite_code) if suite_code is not None else None
    offered = ch.get("offered_versions", []) if ch else []
    return {
        "protocol": email.protocol,
        "server_port": email.server_port,
        "banner": email.banner,
        "implicit_tls": email.implicit_tls,
        "starttls_offered": email.starttls_offered,
        "starttls_used": email.starttls_used,
        "cleartext_auth": email.cleartext_auth,
        "tls_present": email.tls_present,
        "notes": list(email.notes),
        "negotiated_version": negotiated,
        "negotiated_version_name": C.version_name(negotiated) if negotiated else "",
        "offered_versions": [C.version_name(v) for v in offered],
        "deprecated_version": bool(negotiated
                                   and C.is_deprecated_version(negotiated)),
        "sni": ch.get("sni") if ch else None,
        "groups": [C.group_name(g)
                   for g in (ch.get("groups", []) if ch else [])],
        "cipher_suite": suite_code,
        "cipher_suite_name": cs.name if cs else "",
        "cipher_grade": cs.grade if cs else "unknown",
        "cipher_pfs": bool(cs.pfs) if cs else False,
        "cipher_aead": bool(cs.aead) if cs else False,
        "cipher_bits": cs.cipher_bits if cs else 0,
        "cipher_issues": list(cs.issues) if cs else [],
        "cert_count": len(hsx["certs"]),
    }


def _analyze_stream(stream, ml=None) -> SessionResult:
    email = email_detect.detect(stream)
    c_off, s_off = email.client_tls_offset, email.server_tls_offset
    client_tls = stream.client_data[c_off:] if c_off >= 0 else b""
    server_tls = stream.server_data[s_off:] if s_off >= 0 else b""
    hsx = _extract_handshakes(client_tls, server_tls)
    summary = _build_summary(email, hsx)

    chain = analyze_chain(hsx["certs"])
    leaf = dataclasses.asdict(chain.leaf) if chain.leaf else None
    chain_dict = {
        "count": chain.count,
        "chain_complete": chain.chain_complete,
        "self_signed_leaf": chain.self_signed_leaf,
        "leaf": leaf,
    }
    cert_dicts = [dataclasses.asdict(c) for c in chain.chain]

    findings = rules.evaluate(summary, chain_dict)
    feats = features.build(summary, leaf)
    score = posture.score_session(findings)

    res = SessionResult(
        stream=stream.four_tuple,
        protocol=summary["protocol"],
        server_port=summary["server_port"],
        summary=summary,
        certificates=cert_dicts,
        findings=findings,
        features=feats,
        score=score,
        grade=posture.grade(score),
        risk_label=posture.risk_label(findings),
    )
    if ml is not None:
        pred = ml.predict(feats)
        summary["ml_risk"] = pred.get("risk_label")
        summary["ml_confidence"] = pred.get("confidence")
        res.anomaly = bool(pred.get("anomaly"))
        res.anomaly_score = float(pred.get("anomaly_score", 0.0))
    return res


def analyze(path: str, ml=None) -> AnalysisResult:
    """Analyze every email-looking TCP stream in a pcap into an AnalysisResult."""
    streams = reassemble(path)
    candidates = [s for s in streams if s.server_port in _EMAIL_PORTS]
    if not candidates:                    # non-standard ports: analyze all
        candidates = streams
    sessions = [_analyze_stream(s, ml=ml) for s in candidates]
    result = AnalysisResult(source=path, generated_at=now_iso(),
                            tool_version=VERSION, sessions=sessions)
    result.overall_score, result.overall_grade = posture.overall(
        [s.score for s in sessions])
    return result


def full_dict(result: AnalysisResult) -> dict:
    """Serialize a result and attach the prioritized recommendation list."""
    d = result.to_dict()
    d["recommendations"] = recommendations.collect(result.sessions)
    return d
