"""Parsers for the individual TLS handshake messages SecureMailScope cares
about: ClientHello, ServerHello and Certificate. Each returns plain dicts /
lists so downstream code has no dependency on TLS internals.
"""
from __future__ import annotations

from . import constants as C
from .records import Reader


def _parse_extensions(r: Reader) -> dict[int, bytes]:
    exts: dict[int, bytes] = {}
    if r.remaining() < 2:
        return exts
    try:
        total = r.u16()
    except ValueError:
        return exts
    end = min(r.i + total, r.n)
    while r.i + 4 <= end:
        etype = r.u16()
        elen = r.u16()
        if r.i + elen > r.n:
            break
        exts[etype] = r.read(elen)
    return exts


def _sni(ext: bytes) -> str | None:
    try:
        r = Reader(ext)
        r.u16()          # server_name_list length
        r.u8()           # name_type (0 = host_name)
        nlen = r.u16()
        if not nlen:
            return None
        raw = r.read(nlen)
    except Exception:
        return None
    try:
        return raw.decode("idna")
    except Exception:
        return raw.decode("ascii", "replace")


def _u16_list_u8len(ext: bytes) -> list[int]:
    r = Reader(ext)
    blen = r.u8()
    return [r.u16() for _ in range(blen // 2)]


def _u16_list_u16len(ext: bytes) -> list[int]:
    r = Reader(ext)
    blen = r.u16()
    return [r.u16() for _ in range(blen // 2)]


def parse_client_hello(body: bytes) -> dict:
    r = Reader(body)
    legacy = r.u16()
    r.read(32)                          # client random
    r.read(r.u8())                      # legacy session id
    ciphers = [r.u16() for _ in range(r.u16() // 2)]
    r.read(r.u8())                      # compression methods
    exts = _parse_extensions(r)
    offered = ([legacy] if C.EXT_SUPPORTED_VERSIONS not in exts
               else _u16_list_u8len(exts[C.EXT_SUPPORTED_VERSIONS]) or [legacy])
    # TLS 1.3 clients advertise a GREASE-padded list; keep only real versions
    real = [v for v in offered if v in C.VERSION_NAMES] or offered
    return {
        "legacy_version": legacy,
        "offered_versions": real,
        "max_offered_version": max(real),
        "cipher_suites": ciphers,
        "sni": _sni(exts[C.EXT_SERVER_NAME]) if C.EXT_SERVER_NAME in exts else None,
        "groups": (_u16_list_u16len(exts[C.EXT_SUPPORTED_GROUPS])
                   if C.EXT_SUPPORTED_GROUPS in exts else []),
        "has_sig_algs": C.EXT_SIGNATURE_ALGORITHMS in exts,
    }


def parse_server_hello(body: bytes) -> dict:
    r = Reader(body)
    legacy = r.u16()
    r.read(32)                          # server random
    r.read(r.u8())                      # legacy session id echo
    cipher = r.u16()
    r.u8()                              # legacy compression method
    exts = _parse_extensions(r)
    negotiated = legacy
    sv = exts.get(C.EXT_SUPPORTED_VERSIONS)
    if sv and len(sv) >= 2:             # TLS 1.3 signals the real version here
        negotiated = (sv[0] << 8) | sv[1]
    return {
        "legacy_version": legacy,
        "negotiated_version": negotiated,
        "cipher_suite": cipher,
    }


def parse_certificate(body: bytes, tls13: bool = False) -> list[bytes]:
    """Return the DER-encoded certificates from a Certificate message
    (leaf first). TLS 1.3 prepends a request context and appends per-cert
    extensions; both are skipped."""
    r = Reader(body)
    certs: list[bytes] = []
    try:
        if tls13:
            r.read(r.u8())              # certificate_request_context
        end = min(r.i + r.u24(), r.n)   # certificate_list length
        while r.i + 3 <= end:
            clen = r.u24()
            if r.i + clen > r.n:
                break
            certs.append(r.read(clen))
            if tls13 and r.remaining() >= 2:
                r.read(r.u16())         # per-certificate extensions
    except ValueError:
        pass
    return certs
