"""Turn a session summary + leaf certificate into a fixed, numeric feature
vector for the ML layer (and a stable column order shared by training and
inference). Everything is derived from already-parsed facts — no re-parsing.
"""
from __future__ import annotations

_VERSION_ORDINAL = {
    "": 0, "unknown": 0, "none": 0,
    "SSL 2.0": 1, "SSL 3.0": 2, "TLS 1.0": 3,
    "TLS 1.1": 4, "TLS 1.2": 5, "TLS 1.3": 6,
}
_GRADE_ORDINAL = {"insecure": 0, "weak": 1, "unknown": 2,
                  "acceptable": 3, "strong": 4}

FEATURE_NAMES = [
    "tls_present", "implicit_tls", "starttls_offered", "starttls_used",
    "cleartext_auth", "version_ordinal", "deprecated_version",
    "cipher_grade_ordinal", "pfs", "aead", "cipher_bits",
    "rsa_key_bits", "weak_key", "weak_sig", "cert_expired",
    "cert_self_signed", "chain_incomplete", "cert_count",
]


def build(summary: dict, leaf: dict | None) -> dict:
    """Map a session summary (+ optional leaf CertInfo dict) to named features."""
    leaf = leaf or {}
    weaknesses = set(leaf.get("weaknesses", []))
    algo = leaf.get("public_key_algo", "")
    rsa_bits = leaf.get("key_bits", 0) if algo == "RSA" else 0
    weak_key = int(bool({"WEAK_RSA_KEY", "VERY_WEAK_RSA_KEY", "WEAK_EC_KEY",
                         "DSA_KEY"} & weaknesses))
    weak_sig = int(bool({"SHA1_SIG", "MD5_SIG"} & weaknesses))
    return {
        "tls_present": int(bool(summary.get("tls_present"))),
        "implicit_tls": int(bool(summary.get("implicit_tls"))),
        "starttls_offered": int(bool(summary.get("starttls_offered"))),
        "starttls_used": int(bool(summary.get("starttls_used"))),
        "cleartext_auth": int(bool(summary.get("cleartext_auth"))),
        "version_ordinal": _VERSION_ORDINAL.get(
            summary.get("negotiated_version_name", ""), 0),
        "deprecated_version": int(bool(summary.get("deprecated_version"))),
        "cipher_grade_ordinal": _GRADE_ORDINAL.get(
            summary.get("cipher_grade", "unknown"), 2),
        "pfs": int(bool(summary.get("cipher_pfs"))),
        "aead": int(bool(summary.get("cipher_aead"))),
        "cipher_bits": int(summary.get("cipher_bits", 0) or 0),
        "rsa_key_bits": int(rsa_bits or 0),
        "weak_key": weak_key,
        "weak_sig": weak_sig,
        "cert_expired": int("CERT_EXPIRED" in weaknesses),
        "cert_self_signed": int(bool(leaf.get("self_signed"))),
        "chain_incomplete": int("CHAIN_INCOMPLETE" in weaknesses),
        "cert_count": int(summary.get("cert_count", 0) or 0),
    }


def vector(feats: dict) -> list:
    """Flatten a feature dict into a list in the canonical FEATURE_NAMES order."""
    return [float(feats.get(name, 0)) for name in FEATURE_NAMES]
