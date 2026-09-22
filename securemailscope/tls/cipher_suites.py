"""IANA TLS cipher-suite registry (curated subset) annotated with security
properties, so the rules engine can reason about any suite it observes.

Each CipherSuite carries machine-readable `issues` tags (RC4, 3DES, NO_PFS,
CBC, SHA1_MAC, EXPORT, NULL_CIPHER, MD5, ...) consumed by analysis.rules.
grade ∈ {strong, acceptable, weak, insecure, unknown}.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class CipherSuite:
    code: int
    name: str
    kx: str            # key exchange: RSA, DHE, ECDHE
    auth: str          # authentication: RSA, ECDSA, any, NULL
    enc: str           # bulk cipher: AES-128-GCM, AES-256-CBC, 3DES, RC4-128...
    cipher_bits: int   # effective symmetric key length
    mac: str           # SHA, SHA256, SHA384, AEAD, MD5, NULL
    aead: bool
    pfs: bool          # forward secrecy
    grade: str
    issues: tuple = field(default_factory=tuple)


def _s(*a) -> CipherSuite:
    return CipherSuite(*a)


# fmt: off
_SUITES = [
  _s(0x0000,"TLS_NULL_WITH_NULL_NULL","NULL","NULL","NULL",0,"NULL",False,False,"insecure",("NULL_CIPHER","NO_ENCRYPTION")),
  _s(0x0003,"TLS_RSA_EXPORT_WITH_RC4_40_MD5","RSA","RSA","RC4-40",40,"MD5",False,False,"insecure",("EXPORT","RC4","MD5","NO_PFS")),
  _s(0x0004,"TLS_RSA_WITH_RC4_128_MD5","RSA","RSA","RC4-128",128,"MD5",False,False,"insecure",("RC4","MD5","NO_PFS")),
  _s(0x0005,"TLS_RSA_WITH_RC4_128_SHA","RSA","RSA","RC4-128",128,"SHA",False,False,"insecure",("RC4","NO_PFS")),
  _s(0x000A,"TLS_RSA_WITH_3DES_EDE_CBC_SHA","RSA","RSA","3DES",112,"SHA",False,False,"weak",("3DES","SWEET32","NO_PFS","CBC")),
  _s(0x002F,"TLS_RSA_WITH_AES_128_CBC_SHA","RSA","RSA","AES-128-CBC",128,"SHA",False,False,"weak",("NO_PFS","CBC","SHA1_MAC")),
  _s(0x0035,"TLS_RSA_WITH_AES_256_CBC_SHA","RSA","RSA","AES-256-CBC",256,"SHA",False,False,"weak",("NO_PFS","CBC","SHA1_MAC")),
  _s(0x003C,"TLS_RSA_WITH_AES_128_CBC_SHA256","RSA","RSA","AES-128-CBC",128,"SHA256",False,False,"weak",("NO_PFS","CBC")),
  _s(0x009C,"TLS_RSA_WITH_AES_128_GCM_SHA256","RSA","RSA","AES-128-GCM",128,"AEAD",True,False,"acceptable",("NO_PFS",)),
  _s(0x009D,"TLS_RSA_WITH_AES_256_GCM_SHA384","RSA","RSA","AES-256-GCM",256,"AEAD",True,False,"acceptable",("NO_PFS",)),
  _s(0x0033,"TLS_DHE_RSA_WITH_AES_128_CBC_SHA","DHE","RSA","AES-128-CBC",128,"SHA",False,True,"weak",("CBC","SHA1_MAC")),
  _s(0x0039,"TLS_DHE_RSA_WITH_AES_256_CBC_SHA","DHE","RSA","AES-256-CBC",256,"SHA",False,True,"weak",("CBC","SHA1_MAC")),
  _s(0x009E,"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256","DHE","RSA","AES-128-GCM",128,"AEAD",True,True,"strong",()),
  _s(0x009F,"TLS_DHE_RSA_WITH_AES_256_GCM_SHA384","DHE","RSA","AES-256-GCM",256,"AEAD",True,True,"strong",()),
  _s(0xC011,"TLS_ECDHE_RSA_WITH_RC4_128_SHA","ECDHE","RSA","RC4-128",128,"SHA",False,True,"insecure",("RC4",)),
  _s(0xC012,"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA","ECDHE","RSA","3DES",112,"SHA",False,True,"weak",("3DES","SWEET32","CBC")),
  _s(0xC013,"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA","ECDHE","RSA","AES-128-CBC",128,"SHA",False,True,"weak",("CBC","SHA1_MAC")),
  _s(0xC014,"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA","ECDHE","RSA","AES-256-CBC",256,"SHA",False,True,"weak",("CBC","SHA1_MAC")),
  _s(0xC02F,"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256","ECDHE","RSA","AES-128-GCM",128,"AEAD",True,True,"strong",()),
  _s(0xC030,"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384","ECDHE","RSA","AES-256-GCM",256,"AEAD",True,True,"strong",()),
  _s(0xC02B,"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256","ECDHE","ECDSA","AES-128-GCM",128,"AEAD",True,True,"strong",()),
  _s(0xC02C,"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384","ECDHE","ECDSA","AES-256-GCM",256,"AEAD",True,True,"strong",()),
  _s(0xCCA8,"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256","ECDHE","RSA","CHACHA20",256,"AEAD",True,True,"strong",()),
  _s(0xCCA9,"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256","ECDHE","ECDSA","CHACHA20",256,"AEAD",True,True,"strong",()),
  _s(0x1301,"TLS_AES_128_GCM_SHA256","ECDHE","any","AES-128-GCM",128,"AEAD",True,True,"strong",()),
  _s(0x1302,"TLS_AES_256_GCM_SHA384","ECDHE","any","AES-256-GCM",256,"AEAD",True,True,"strong",()),
  _s(0x1303,"TLS_CHACHA20_POLY1305_SHA256","ECDHE","any","CHACHA20",256,"AEAD",True,True,"strong",()),
]
# fmt: on

REGISTRY: dict[int, CipherSuite] = {c.code: c for c in _SUITES}


def lookup(code: int) -> CipherSuite:
    c = REGISTRY.get(code)
    if c is not None:
        return c
    return CipherSuite(code, f"UNKNOWN_0x{code:04X}", "?", "?", "?", 0, "?",
                       False, False, "unknown", ("UNKNOWN_SUITE",))


def name(code: int) -> str:
    return lookup(code).name
