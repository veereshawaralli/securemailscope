"""Pure-Python PCAP reader + Ethernet/IPv4/TCP dissection + TCP stream
reassembly. No libpcap, tshark, scapy or dpkt — just the stdlib — so the
zero-credential demo runs anywhere Python does.

Supports the classic pcap format (little/big endian) with Ethernet, raw-IP
and null/loopback link types. pcapng is detected and reported (convert with
`tshark -F pcap` / `editcap`).
"""
from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field

LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LOOP = 108

_MAGIC_LE = b"\xd4\xc3\xb2\xa1"
_MAGIC_BE = b"\xa1\xb2\xc3\xd4"
_MAGIC_LE_NS = b"\x4d\x3c\xb2\xa1"
_MAGIC_BE_NS = b"\xa1\xb2\x3c\x4d"
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

TCP_FIN, TCP_SYN, TCP_RST, TCP_PSH, TCP_ACK = 0x01, 0x02, 0x04, 0x08, 0x10


def read_frames(path: str):
    """Yield (ts_float, linktype, frame_bytes) for each captured packet."""
    with open(path, "rb") as fh:
        blob = fh.read()
    if blob[:4] == _PCAPNG_MAGIC:
        raise ValueError("pcapng not supported — run: tshark -r in.pcapng "
                         "-F pcap -w out.pcap")
    magic = blob[:4]
    if magic in (_MAGIC_LE, _MAGIC_LE_NS):
        e = "<"
    elif magic in (_MAGIC_BE, _MAGIC_BE_NS):
        e = ">"
    else:
        raise ValueError("not a classic pcap file (bad magic)")
    (_vmaj, _vmin, _tz, _sig, _snap, linktype) = struct.unpack(
        e + "HHiIII", blob[4:24])
    off = 24
    n = len(blob)
    while off + 16 <= n:
        ts_sec, ts_usec, incl, _orig = struct.unpack(e + "IIII", blob[off:off + 16])
        off += 16
        if off + incl > n:
            break
        frame = blob[off:off + incl]
        off += incl
        yield (ts_sec + ts_usec / 1e6, linktype, frame)


def _l3_from_frame(linktype: int, data: bytes) -> bytes | None:
    """Strip the link layer, returning the IPv4 packet bytes (or None)."""
    if linktype == LINKTYPE_ETHERNET:
        if len(data) < 14:
            return None
        etype = (data[12] << 8) | data[13]
        off = 14
        if etype == 0x8100 and len(data) >= 18:      # 802.1Q VLAN tag
            etype = (data[16] << 8) | data[17]
            off = 18
        return data[off:] if etype == 0x0800 else None
    if linktype == LINKTYPE_RAW:
        return data
    if linktype in (LINKTYPE_NULL, LINKTYPE_LOOP):
        return data[4:] if len(data) > 4 else None
    return None


def _parse_ipv4(pkt: bytes):
    if len(pkt) < 20 or (pkt[0] >> 4) != 4:
        return None
    ihl = (pkt[0] & 0x0F) * 4
    if len(pkt) < ihl or ihl < 20:
        return None
    proto = pkt[9]
    total_len = (pkt[2] << 8) | pkt[3]
    src = socket.inet_ntoa(pkt[12:16])
    dst = socket.inet_ntoa(pkt[16:20])
    end = total_len if 0 < total_len <= len(pkt) else len(pkt)
    return src, dst, proto, pkt[ihl:end]


def _parse_tcp(seg: bytes):
    if len(seg) < 20:
        return None
    sport = (seg[0] << 8) | seg[1]
    dport = (seg[2] << 8) | seg[3]
    seq = struct.unpack(">I", seg[4:8])[0]
    off = (seg[12] >> 4) * 4
    flags = seg[13]
    if off < 20 or len(seg) < off:
        return None
    return sport, dport, seq, flags, seg[off:]


@dataclass
class TcpStream:
    """One reassembled TCP connection with both directions of payload."""
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    client_data: bytes = b""
    server_data: bytes = b""
    start_ts: float = 0.0
    packets: int = 0
    saw_syn: bool = False

    @property
    def four_tuple(self) -> str:
        return (f"{self.client_ip}:{self.client_port} -> "
                f"{self.server_ip}:{self.server_port}")


_EMAIL_SERVER_PORTS = {25, 465, 587, 143, 993, 110, 995}


def _reassemble_dir(segs) -> bytes:
    """Order payload segments by sequence number into a contiguous stream."""
    if not segs:
        return b""
    base = min(s for s, _ in segs)
    buf = bytearray()
    for seq, data in sorted(segs, key=lambda x: x[0]):
        off = (seq - base) & 0xFFFFFFFF
        if off > 16_000_000:          # sequence wrap / bogus — skip safely
            continue
        if off + len(data) > len(buf):
            buf.extend(b"\x00" * (off + len(data) - len(buf)))
        buf[off:off + len(data)] = data
    return bytes(buf)


def _finalize(key, c) -> TcpStream:
    e0, e1 = list(key)
    client = c["client"]
    if client is not None:
        server = e1 if client == e0 else e0
    elif e0[1] in _EMAIL_SERVER_PORTS and e1[1] not in _EMAIL_SERVER_PORTS:
        server, client = e0, e1
    elif e1[1] in _EMAIL_SERVER_PORTS and e0[1] not in _EMAIL_SERVER_PORTS:
        server, client = e1, e0
    else:                              # lower port is conventionally the server
        server, client = (e0, e1) if e0[1] <= e1[1] else (e1, e0)
    cdata = _reassemble_dir(c["segs"].get((client, server), []))
    sdata = _reassemble_dir(c["segs"].get((server, client), []))
    return TcpStream(client[0], client[1], server[0], server[1],
                     cdata, sdata, c["ts"], c["npkts"], c["syn"])


def reassemble(path: str) -> list[TcpStream]:
    """Read a pcap and return one TcpStream per TCP connection."""
    conns: dict = {}
    for ts, linktype, frame in read_frames(path):
        pkt = _l3_from_frame(linktype, frame)
        if pkt is None:
            continue
        ipp = _parse_ipv4(pkt)
        if ipp is None or ipp[2] != 6:      # IPv4 + TCP only
            continue
        src, dst, _proto, l4 = ipp
        tcp = _parse_tcp(l4)
        if tcp is None:
            continue
        sport, dport, seq, flags, payload = tcp
        a, b = (src, sport), (dst, dport)
        c = conns.get(frozenset((a, b)))
        if c is None:
            c = conns[frozenset((a, b))] = {
                "segs": {}, "client": None, "ts": ts, "npkts": 0, "syn": False}
        c["npkts"] += 1
        if flags & TCP_SYN:
            c["syn"] = True
            c["client"] = b if (flags & TCP_ACK) else a
        if payload:
            c["segs"].setdefault((a, b), []).append((seq, payload))
    return [_finalize(k, c) for k, c in conns.items()]
