"""X.509 certificate extraction, validation and cryptographic analysis.

Uses `cryptography` when available (real DER parsing plus key / signature /
expiry inspection). If the library is missing the module degrades gracefully:
the certificate is still reported as present so posture scoring can proceed.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime, timezone

try:
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import (
        dsa, ec, ed448, ed25519, padding, rsa)
    _HAVE_CRYPTO = True
except Exception:            # pragma: no cover
    _HAVE_CRYPTO = False


@dataclass
class CertInfo:
    present: bool = True
    parsed: bool = False
    subject: str = ""
    issuer: str = ""
    serial: str = ""
    version: str = ""
    not_before: str = ""
    not_after: str = ""
    days_to_expiry: int | None = None
    is_expired: bool = False
    not_yet_valid: bool = False
    public_key_algo: str = ""
    key_bits: int = 0
    sig_hash: str = ""
    sig_algo: str = ""
    self_signed: bool = False
    is_ca: bool = False
    san: list = field(default_factory=list)
    weaknesses: list = field(default_factory=list)
    error: str = ""


@dataclass
class ChainInfo:
    count: int = 0
    leaf: "CertInfo | None" = None
    chain: list = field(default_factory=list)
    chain_complete: bool = False
    self_signed_leaf: bool = False
    # cryptographic path-validation results (populated when `cryptography`
    # is available and at least one signature link can be checked)
    signatures_valid: "bool | None" = None   # None = nothing verifiable
    self_signed_root: bool = False
    trusted_anchor: "bool | None" = None      # None = no trust store loaded
    validated: bool = False                   # sigs valid AND reaches an anchor
    anchor_subject: str = ""
    trust_status: str = ""                    # trusted|private-ca|self-signed|…
    trust_detail: str = ""


def _now():
    return datetime.now(timezone.utc)


def _aware(dt):
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _key_info(pk):
    if not _HAVE_CRYPTO:
        return type(pk).__name__, 0
    if isinstance(pk, rsa.RSAPublicKey):
        return "RSA", pk.key_size
    if isinstance(pk, ec.EllipticCurvePublicKey):
        return f"EC ({pk.curve.name})", pk.curve.key_size
    if isinstance(pk, dsa.DSAPublicKey):
        return "DSA", pk.key_size
    if isinstance(pk, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    if isinstance(pk, ed448.Ed448PublicKey):
        return "Ed448", 456
    return type(pk).__name__, 0


def _validity_dates(cert):
    try:                                  # cryptography >= 42
        return cert.not_valid_before_utc, cert.not_valid_after_utc
    except AttributeError:                # older releases: naive UTC
        return _aware(cert.not_valid_before), _aware(cert.not_valid_after)


def _flag_cert_weaknesses(info: "CertInfo") -> None:
    w = info.weaknesses
    if info.is_expired:
        w.append("CERT_EXPIRED")
    elif info.days_to_expiry is not None and info.days_to_expiry < 30:
        w.append("CERT_EXPIRING_SOON")
    if info.not_yet_valid:
        w.append("CERT_NOT_YET_VALID")
    if info.public_key_algo == "RSA":
        if info.key_bits < 1024:
            w.append("VERY_WEAK_RSA_KEY")
        elif info.key_bits < 2048:
            w.append("WEAK_RSA_KEY")
    if info.public_key_algo.startswith("EC") and 0 < info.key_bits < 256:
        w.append("WEAK_EC_KEY")
    if info.public_key_algo == "DSA":
        w.append("DSA_KEY")
    h = (info.sig_hash or "").lower()
    if h == "md5":
        w.append("MD5_SIG")
    elif h == "sha1":
        w.append("SHA1_SIG")
    if info.self_signed:
        w.append("SELF_SIGNED")


def analyze_cert(der: bytes) -> "CertInfo":
    """Parse one DER-encoded certificate into a CertInfo with weakness tags."""
    info = CertInfo(present=True)
    if not _HAVE_CRYPTO:
        info.error = "cryptography not installed — DER not parsed"
        info.weaknesses.append("CERT_NOT_ANALYZED")
        return info
    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception as e:                # pragma: no cover
        info.error = f"parse error: {e}"
        info.weaknesses.append("CERT_PARSE_ERROR")
        return info

    info.parsed = True
    info.subject = cert.subject.rfc4514_string()
    info.issuer = cert.issuer.rfc4514_string()
    info.serial = f"{cert.serial_number:x}"
    info.version = cert.version.name
    nb, na = _validity_dates(cert)
    now = _now()
    info.not_before, info.not_after = nb.isoformat(), na.isoformat()
    info.days_to_expiry = (na - now).days
    info.is_expired = na < now
    info.not_yet_valid = nb > now
    info.self_signed = cert.subject == cert.issuer
    info.public_key_algo, info.key_bits = _key_info(cert.public_key())
    try:
        alg = cert.signature_hash_algorithm
        info.sig_hash = alg.name if alg else "none"
    except Exception:
        info.sig_hash = "unknown"
    info.sig_algo = getattr(cert.signature_algorithm_oid, "_name",
                            cert.signature_algorithm_oid.dotted_string)
    try:
        san = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName).value
        info.san = list(san.get_values_for_type(x509.DNSName))
    except Exception:
        info.san = []
    try:
        info.is_ca = cert.extensions.get_extension_for_class(
            x509.BasicConstraints).value.ca
    except Exception:
        info.is_ca = False
    _flag_cert_weaknesses(info)
    return info


# ── chain / trust-path validation ───────────────────────────────────────────
_ANCHORS: "dict | None" = None            # cached subject -> [trusted certs]


def _verify_signed_by(child, issuer_pub) -> "bool | None":
    """Cryptographically verify `child`'s signature against `issuer_pub`.

    Returns True (valid), False (signature does not verify) or None (the
    signature scheme could not be checked — treated as inconclusive, never a
    false accusation of tampering)."""
    if not _HAVE_CRYPTO:
        return None
    try:
        sig = child.signature
        tbs = child.tbs_certificate_bytes
        halg = child.signature_hash_algorithm
        if isinstance(issuer_pub, rsa.RSAPublicKey):
            name = (getattr(child.signature_algorithm_oid, "_name", "") or "")
            if "pss" in name.lower():     # RSA-PSS needs different params
                return None
            issuer_pub.verify(sig, tbs, padding.PKCS1v15(), halg)
        elif isinstance(issuer_pub, ec.EllipticCurvePublicKey):
            issuer_pub.verify(sig, tbs, ec.ECDSA(halg))
        elif isinstance(issuer_pub, ed25519.Ed25519PublicKey):
            issuer_pub.verify(sig, tbs)
        elif isinstance(issuer_pub, ed448.Ed448PublicKey):
            issuer_pub.verify(sig, tbs)
        else:
            return None
        return True
    except InvalidSignature:
        return False
    except Exception:
        return None


def _split_pem(pem: bytes) -> list:      # pragma: no cover - old cryptography
    out, marker = [], b"-----BEGIN CERTIFICATE-----"
    for chunk in pem.split(marker)[1:]:
        block = marker + chunk.split(b"-----END CERTIFICATE-----")[0] \
            + b"-----END CERTIFICATE-----\n"
        try:
            out.append(x509.load_pem_x509_certificate(block))
        except Exception:
            pass
    return out


def _load_trust_anchors() -> dict:
    """Best-effort load of the local root store (certifi, else the OpenSSL
    default CA file). Cached. Returns {subject_rfc4514: [x509.Certificate]};
    an empty dict means no store was found (trust becomes 'unknown')."""
    global _ANCHORS
    if _ANCHORS is not None:
        return _ANCHORS
    _ANCHORS = {}
    if not _HAVE_CRYPTO:
        return _ANCHORS
    pem = b""
    try:
        import certifi
        with open(certifi.where(), "rb") as fh:
            pem = fh.read()
    except Exception:
        try:
            import ssl
            cafile = ssl.get_default_verify_paths().cafile
            if cafile and os.path.isfile(cafile):
                with open(cafile, "rb") as fh:
                    pem = fh.read()
        except Exception:
            pem = b""
    if not pem:
        return _ANCHORS
    try:
        certs = x509.load_pem_x509_certificates(pem)   # cryptography >= 39
    except Exception:                                  # pragma: no cover
        certs = _split_pem(pem)
    idx: dict = {}
    for c in certs:
        idx.setdefault(c.subject.rfc4514_string(), []).append(c)
    _ANCHORS = idx
    return _ANCHORS


def _same_public_key(a, b) -> bool:
    try:
        enc, fmt = (serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo)
        return (a.public_key().public_bytes(enc, fmt)
                == b.public_key().public_bytes(enc, fmt))
    except Exception:
        return False


def _anchor_trust(certs, anchors) -> "bool | None":
    """Does the presented chain terminate in a certificate in `anchors`?
    None when no trust store is available."""
    if not anchors:
        return None
    top = certs[-1]
    if top.subject == top.issuer:            # self-signed root: match identity
        for cand in anchors.get(top.subject.rfc4514_string(), []):
            if _same_public_key(cand, top):
                return True
        return False
    for cand in anchors.get(top.issuer.rfc4514_string(), []):
        if _verify_signed_by(top, cand.public_key()) is True:
            return True
    return False


def _verify_chain(ch: "ChainInfo", ders: list, trust_anchors) -> None:
    """Populate ch.signatures_valid / self_signed_root / trusted_anchor via
    real signature checks over the presented (leaf-first) certificate list."""
    if not _HAVE_CRYPTO:
        return
    try:
        certs = [x509.load_der_x509_certificate(d) for d in ders]
    except Exception:                        # pragma: no cover
        return
    results = [_verify_signed_by(certs[i], certs[i + 1].public_key())
               for i in range(len(certs) - 1)]
    top = certs[-1]
    ch.self_signed_root = top.subject == top.issuer
    if ch.self_signed_root:
        results.append(_verify_signed_by(top, top.public_key()))
    if any(r is False for r in results):
        ch.signatures_valid = False
    elif results and all(r is True for r in results):
        ch.signatures_valid = True
    else:
        ch.signatures_valid = None           # nothing conclusive to check
    anchors = trust_anchors if trust_anchors is not None else _load_trust_anchors()
    ch.trusted_anchor = _anchor_trust(certs, anchors)
    ch.anchor_subject = (top.subject if ch.self_signed_root
                         else top.issuer).rfc4514_string()
    ch.validated = (ch.signatures_valid is True
                    and (ch.trusted_anchor is True or ch.self_signed_root))


def _derive_trust_status(ch: "ChainInfo") -> tuple:
    if ch.count == 0:
        return "", ""
    if ch.signatures_valid is False:
        return "broken", ("a certificate is not validly signed by the issuer "
                          "presented above it in the chain")
    if ch.trusted_anchor is True:
        return "trusted", "chain verifies to a root in the local trust store"
    if ch.self_signed_root:
        if ch.count == 1:
            return "self-signed", "single self-signed certificate (no CA chain)"
        return "private-ca", ("internally consistent chain to a self-signed "
                              "(private / self-managed) root")
    if ch.signatures_valid is True:
        return "unanchored", ("signatures verify but the chain does not reach a "
                              "known public trust anchor")
    return "unverified", "chain could not be fully verified (issuer not presented)"


def analyze_chain(ders: list, trust_anchors: "dict | None" = None) -> "ChainInfo":
    """Analyze a leaf-first list of DER certificates as a presented chain.

    Beyond name-based completeness this performs real cryptographic path
    validation: each certificate's signature is verified against the public key
    of the certificate above it, the terminal (root) certificate is checked for
    self-signature, and the chain is tested against a trust store to decide
    whether it anchors to a trusted root. `trust_anchors` overrides the
    auto-loaded store (subject_rfc4514 -> [x509.Certificate])."""
    ch = ChainInfo(count=len(ders))
    if not ders:
        return ch
    ch.chain = [analyze_cert(d) for d in ders]
    ch.leaf = ch.chain[0]
    ch.self_signed_leaf = bool(ch.leaf.self_signed)
    linked = all(ch.chain[i].issuer == ch.chain[i + 1].subject
                 for i in range(len(ch.chain) - 1))
    ch.chain_complete = linked and bool(ch.chain[-1].self_signed)
    if not ch.chain_complete and not ch.self_signed_leaf:
        ch.leaf.weaknesses.append("CHAIN_INCOMPLETE")
    _verify_chain(ch, ders, trust_anchors)
    if ch.signatures_valid is False and \
            "CHAIN_SIGNATURE_INVALID" not in ch.leaf.weaknesses:
        ch.leaf.weaknesses.append("CHAIN_SIGNATURE_INVALID")
    ch.trust_status, ch.trust_detail = _derive_trust_status(ch)
    return ch
