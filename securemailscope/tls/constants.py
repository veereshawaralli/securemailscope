"""TLS protocol constants and small helpers shared by the parser and the
synthetic-capture generator. Values are the on-the-wire numeric identifiers
from the TLS RFCs / IANA registries.
"""
from __future__ import annotations

# ── Record content types (TLS record layer) ────────────────────────────────
CT_CHANGE_CIPHER_SPEC = 20
CT_ALERT = 21
CT_HANDSHAKE = 22
CT_APPLICATION_DATA = 23

# ── Handshake message types ─────────────────────────────────────────────────
HS_CLIENT_HELLO = 1
HS_SERVER_HELLO = 2
HS_CERTIFICATE = 11
HS_SERVER_KEY_EXCHANGE = 12
HS_CERTIFICATE_REQUEST = 13
HS_SERVER_HELLO_DONE = 14
HS_CLIENT_KEY_EXCHANGE = 16

# ── Protocol versions (major << 8 | minor) ──────────────────────────────────
SSL_2_0 = 0x0200
SSL_3_0 = 0x0300
TLS_1_0 = 0x0301
TLS_1_1 = 0x0302
TLS_1_2 = 0x0303
TLS_1_3 = 0x0304

VERSION_NAMES = {
    SSL_2_0: "SSL 2.0", SSL_3_0: "SSL 3.0", TLS_1_0: "TLS 1.0",
    TLS_1_1: "TLS 1.1", TLS_1_2: "TLS 1.2", TLS_1_3: "TLS 1.3",
}

# RFC 8996 deprecates TLS 1.0/1.1; SSL 2.0/3.0 are broken (DROWN, POODLE).
DEPRECATED_VERSIONS = {SSL_2_0, SSL_3_0, TLS_1_0, TLS_1_1}

# ── Extension types ─────────────────────────────────────────────────────────
EXT_SERVER_NAME = 0
EXT_SUPPORTED_GROUPS = 10
EXT_SIGNATURE_ALGORITHMS = 13
EXT_SUPPORTED_VERSIONS = 43

NAMED_GROUPS = {
    0x0017: "secp256r1", 0x0018: "secp384r1", 0x0019: "secp521r1",
    0x001d: "x25519", 0x001e: "x448",
    0x0100: "ffdhe2048", 0x0101: "ffdhe3072", 0x0102: "ffdhe4096",
}


def version_name(v: int) -> str:
    return VERSION_NAMES.get(v, f"0x{v:04x}")


def is_deprecated_version(v: int) -> bool:
    return v in DEPRECATED_VERSIONS


def group_name(g: int) -> str:
    return NAMED_GROUPS.get(g, f"0x{g:04x}")
