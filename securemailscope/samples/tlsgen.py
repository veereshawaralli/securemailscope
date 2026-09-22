"""Builders for synthetic X.509 certificates and TLS handshake messages, used
only by the sample generator. Certificates are real (signed with `cryptography`);
handshake messages are hand-encoded to match the on-the-wire layout the parser
in `securemailscope.tls` expects. Nothing here is used at analysis time.
"""
from __future__ import annotations

import struct
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID


def gen_key(kind: str = "rsa2048"):
    if kind == "rsa1024":
        return rsa.generate_private_key(public_exponent=65537, key_size=1024)
    if kind == "rsa4096":
        return rsa.generate_private_key(public_exponent=65537, key_size=4096)
    if kind == "ec256":
        return ec.generate_private_key(ec.SECP256R1())
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make_cert(cn, key, issuer_cn, issuer_key, *, days_from=-30, days_to=365,
              sig="sha256", ca=False, sans=None) -> bytes:
    """Build and sign a DER certificate. `sig` in {sha256, sha384, sha1, md5}."""
    now = datetime.now(timezone.utc)
    hash_map = {"sha256": hashes.SHA256(), "sha384": hashes.SHA384(),
                "sha1": hashes.SHA1(), "md5": hashes.MD5()}
    algo = hash_map.get(sig, hashes.SHA256())
    b = (x509.CertificateBuilder()
         .subject_name(_name(cn)).issuer_name(_name(issuer_cn))
         .public_key(key.public_key())
         .serial_number(x509.random_serial_number())
         .not_valid_before(now + timedelta(days=days_from))
         .not_valid_after(now + timedelta(days=days_to)))
    if ca:
        b = b.add_extension(x509.BasicConstraints(ca=True, path_length=None),
                            critical=True)
    if sans:
        b = b.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]),
            critical=False)
    try:
        cert = b.sign(issuer_key, algo)
    except Exception:                     # e.g. MD5/SHA1 disallowed by backend
        cert = b.sign(issuer_key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.DER)


# ── TLS handshake / record encoders ─────────────────────────────────────────
def _u24(n: int) -> bytes:
    return struct.pack(">I", n)[1:]


def _hs(msg_type: int, body: bytes) -> bytes:
    return bytes([msg_type]) + _u24(len(body)) + body


def record(content_type: int, version: int, payload: bytes) -> bytes:
    return bytes([content_type]) + struct.pack(">HH", version, len(payload)) + payload


def client_hello(legacy_version, ciphers, sni=None,
                 supported_versions=None, groups=None) -> bytes:
    b = struct.pack(">H", legacy_version) + b"\x11" * 32 + b"\x00"
    cs = b"".join(struct.pack(">H", c) for c in ciphers)
    b += struct.pack(">H", len(cs)) + cs + b"\x01\x00"   # compression: null
    exts = b""
    if sni:
        host = sni.encode()
        names = b"\x00" + struct.pack(">H", len(host)) + host
        block = struct.pack(">H", len(names)) + names
        exts += struct.pack(">HH", 0, len(block)) + block
    if supported_versions:
        sv = bytes([len(supported_versions) * 2]) + b"".join(
            struct.pack(">H", v) for v in supported_versions)
        exts += struct.pack(">HH", 43, len(sv)) + sv
    if groups:
        gl = b"".join(struct.pack(">H", g) for g in groups)
        block = struct.pack(">H", len(gl)) + gl
        exts += struct.pack(">HH", 10, len(block)) + block
    sa = struct.pack(">H", 2) + b"\x04\x03"              # signature_algorithms
    exts += struct.pack(">HH", 13, len(sa)) + sa
    b += struct.pack(">H", len(exts)) + exts
    return record(22, 0x0301, _hs(1, b))


def server_hello(legacy_version, cipher, supported_version=None) -> bytes:
    b = struct.pack(">H", legacy_version) + b"\x22" * 32 + b"\x00"
    b += struct.pack(">H", cipher) + b"\x00"
    exts = b""
    if supported_version:
        sv = struct.pack(">H", supported_version)
        exts += struct.pack(">HH", 43, len(sv)) + sv
    b += struct.pack(">H", len(exts)) + exts
    return record(22, 0x0303, _hs(2, b))


def certificate(ders) -> bytes:
    entries = b"".join(_u24(len(d)) + d for d in ders)
    return record(22, 0x0303, _hs(11, _u24(len(entries)) + entries))


def encrypted_blob(nbytes: int = 512) -> bytes:
    """A stand-in application_data record (e.g. TLS 1.3 encrypted cert)."""
    return record(23, 0x0303, bytes((i * 7 + 11) & 0xFF for i in range(nbytes)))
