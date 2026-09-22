"""Pure-Python classic-pcap writer plus Ethernet/IPv4/TCP frame builders with
correct internet checksums, so generated captures open cleanly in Wireshark.
Used only by the synthetic sample generator; the analyzer never needs it.
"""
from __future__ import annotations

import socket
import struct

_ETH_CLIENT_MAC = bytes.fromhex("020000000001")
_ETH_SERVER_MAC = bytes.fromhex("020000000002")
_ETHERTYPE_IPV4 = 0x0800

TCP_FIN, TCP_SYN, TCP_RST, TCP_PSH, TCP_ACK = 0x01, 0x02, 0x04, 0x08, 0x10


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum((data[i] << 8) | data[i + 1] for i in range(0, len(data), 2))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def _ipv4(src: str, dst: str, proto: int, payload: bytes, ident: int) -> bytes:
    total = 20 + len(payload)
    hdr = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, ident & 0xFFFF,
                      0x4000, 64, proto, 0,
                      socket.inet_aton(src), socket.inet_aton(dst))
    chk = _checksum(hdr)
    hdr = hdr[:10] + struct.pack(">H", chk) + hdr[12:]
    return hdr + payload


def _tcp(src: str, dst: str, sport: int, dport: int, seq: int, ack: int,
         flags: int, payload: bytes) -> bytes:
    hdr = struct.pack(">HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF,
                      ack & 0xFFFFFFFF, (5 << 4), flags, 65535, 0, 0)
    pseudo = struct.pack(">4s4sBBH", socket.inet_aton(src),
                         socket.inet_aton(dst), 0, 6, len(hdr) + len(payload))
    chk = _checksum(pseudo + hdr + payload)
    hdr = hdr[:16] + struct.pack(">H", chk) + hdr[18:]
    return hdr + payload


def tcp_frame(src_ip: str, dst_ip: str, sport: int, dport: int, seq: int,
              ack: int, flags: int, payload: bytes = b"",
              from_client: bool = True) -> bytes:
    """Build a full Ethernet+IPv4+TCP frame."""
    seg = _tcp(src_ip, dst_ip, sport, dport, seq, ack, flags, payload)
    ip = _ipv4(src_ip, dst_ip, 6, seg, ident=(seq ^ sport) & 0xFFFF)
    src_mac = _ETH_CLIENT_MAC if from_client else _ETH_SERVER_MAC
    dst_mac = _ETH_SERVER_MAC if from_client else _ETH_CLIENT_MAC
    return struct.pack(">6s6sH", dst_mac, src_mac, _ETHERTYPE_IPV4) + ip


class PcapWriter:
    """Minimal classic-pcap (little-endian, Ethernet link type) writer."""

    def __init__(self, path: str):
        self._fh = open(path, "wb")
        self._fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0,
                                   262144, 1))

    def write(self, ts: float, frame: bytes) -> None:
        sec = int(ts)
        usec = int((ts - sec) * 1_000_000)
        self._fh.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
        self._fh.write(frame)

    def close(self) -> None:
        self._fh.close()

    def __enter__(self) -> "PcapWriter":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
