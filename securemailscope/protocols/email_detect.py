"""Detect the application-layer email protocol (SMTP / IMAP / POP3), STARTTLS
upgrades and cleartext-credential exposure from a reassembled TCP stream, and
locate the byte offset where the TLS handshake begins in each direction.

The offsets let the TLS layer parse handshakes that appear either at connect
time (implicit TLS: SMTPS/IMAPS/POP3S) or after a STARTTLS/STLS upgrade on an
originally cleartext port.
"""
from __future__ import annotations

from dataclasses import dataclass, field

SMTP, IMAP, POP3, UNKNOWN = "SMTP", "IMAP", "POP3", "UNKNOWN"

_PORT_PROTO = {25: SMTP, 587: SMTP, 465: SMTP,
               143: IMAP, 993: IMAP, 110: POP3, 995: POP3}
_IMPLICIT_TLS_PORTS = {465, 993, 995}


def find_tls_start(data: bytes) -> int:
    """Return the offset of the first plausible TLS *handshake* record, or -1.
    Anchors on content-type 22 (handshake), legacy version 0x03xx and a sane
    record length — enough to separate a plaintext prefix from TLS bytes."""
    n = len(data)
    for i in range(0, max(0, n - 4)):
        if data[i] == 0x16 and data[i + 1] == 0x03 and data[i + 2] <= 0x04:
            length = (data[i + 3] << 8) | data[i + 4]
            if 0 < length <= 0x4000:
                return i
    return -1


@dataclass
class EmailAnalysis:
    protocol: str
    server_port: int
    implicit_tls: bool
    starttls_offered: bool
    starttls_used: bool
    cleartext_auth: bool
    tls_present: bool
    client_tls_offset: int
    server_tls_offset: int
    banner: str = ""
    notes: list = field(default_factory=list)


def _first_line(data: bytes) -> str:
    return data.split(b"\r\n", 1)[0][:200].decode("latin-1", "replace")


def _sniff_proto(su: bytes, cu: bytes) -> str:
    if su.startswith(b"* OK") or b"CAPABILITY" in cu:
        return IMAP
    if su.startswith(b"+OK") or b"USER " in cu:
        return POP3
    if su.startswith(b"220") or b"EHLO" in cu or b"HELO" in cu:
        return SMTP
    return UNKNOWN


def _has_cleartext_auth(cu: bytes, proto: str) -> bool:
    if proto == SMTP:
        return b"AUTH LOGIN" in cu or b"AUTH PLAIN" in cu
    if proto == POP3:
        return b"USER " in cu or b"PASS " in cu
    if proto == IMAP:
        return b"LOGIN " in cu
    return False


def detect(stream) -> EmailAnalysis:
    port = stream.server_port
    cdata, sdata = stream.client_data, stream.server_data
    c_off = find_tls_start(cdata)
    s_off = find_tls_start(sdata)
    tls_present = c_off >= 0 or s_off >= 0

    c_plain = cdata[:c_off] if c_off >= 0 else cdata
    s_plain = sdata[:s_off] if s_off >= 0 else sdata
    cu, su = c_plain.upper(), s_plain.upper()

    proto = _PORT_PROTO.get(port) or _sniff_proto(su, cu)
    implicit = port in _IMPLICIT_TLS_PORTS or (tls_present and not s_plain.strip())
    starttls_offered = b"STARTTLS" in su or b"STLS" in su
    starttls_used = (b"STARTTLS" in cu or b"STLS" in cu) and tls_present and not implicit
    cleartext_auth = _has_cleartext_auth(cu, proto)

    notes: list[str] = []
    if implicit:
        notes.append("Implicit TLS (SMTPS/IMAPS/POP3S): encrypted from connect.")
    if starttls_used:
        notes.append("STARTTLS upgrade observed on a cleartext-capable port.")
    if starttls_offered and not starttls_used and not implicit and not tls_present:
        notes.append("STARTTLS advertised but never used — downgrade/stripping risk.")
    if cleartext_auth:
        notes.append("Credentials transmitted before encryption (cleartext auth).")

    return EmailAnalysis(proto, port, implicit, starttls_offered, starttls_used,
                         cleartext_auth, tls_present, c_off, s_off,
                         _first_line(s_plain), notes)
