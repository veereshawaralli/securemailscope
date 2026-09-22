"""TLS record-layer parsing over a reassembled byte stream.

Tolerant of truncation and of records that split or coalesce handshake
messages (both are legal on the wire). `Reader` is a tiny big-endian cursor
reused by the handshake parser.
"""
from __future__ import annotations

from dataclasses import dataclass

from . import constants as C


class Reader:
    """Big-endian byte cursor that raises ValueError on short reads."""
    __slots__ = ("d", "i", "n")

    def __init__(self, data: bytes):
        self.d = data
        self.i = 0
        self.n = len(data)

    def remaining(self) -> int:
        return self.n - self.i

    def read(self, k: int) -> bytes:
        if k < 0 or self.i + k > self.n:
            raise ValueError("short read")
        b = self.d[self.i:self.i + k]
        self.i += k
        return b

    def u8(self) -> int:
        return self.read(1)[0]

    def u16(self) -> int:
        b = self.read(2)
        return (b[0] << 8) | b[1]

    def u24(self) -> int:
        b = self.read(3)
        return (b[0] << 16) | (b[1] << 8) | b[2]


@dataclass
class TlsRecord:
    content_type: int
    version: int
    payload: bytes


def iter_records(data: bytes):
    """Yield TLS records, stopping at the first malformed/truncated record
    (expected at capture boundaries or once traffic turns into ciphertext)."""
    r = Reader(data)
    while r.remaining() >= 5:
        start = r.i
        try:
            ct = r.u8()
            ver = r.u16()
            length = r.u16()
            payload = r.read(length)
        except ValueError:
            break
        if ct not in (C.CT_CHANGE_CIPHER_SPEC, C.CT_ALERT,
                      C.CT_HANDSHAKE, C.CT_APPLICATION_DATA):
            break  # not a TLS stream (or desynchronised) — stop cleanly
        if (ver >> 8) not in (0x03,):  # TLS/SSL major version is always 3
            r.i = start
            break
        yield TlsRecord(ct, ver, payload)


@dataclass
class HandshakeMessage:
    msg_type: int
    body: bytes


def iter_handshakes(records):
    """Reassemble handshake messages from all handshake-type record payloads,
    then split them by their 1-byte type + 3-byte length headers."""
    buf = b"".join(rec.payload for rec in records
                   if rec.content_type == C.CT_HANDSHAKE)
    r = Reader(buf)
    while r.remaining() >= 4:
        try:
            mtype = r.u8()
            mlen = r.u24()
            body = r.read(mlen)
        except ValueError:
            break
        yield HandshakeMessage(mtype, body)
