"""X.509 certificate extraction, validation and cryptographic analysis.

Uses `cryptography` when available (real DER parsing plus key / signature /
expiry inspection). If the library is missing the module degrades gracefully:
the certificate is still reported as present so posture scoring can proceed.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import (
        dsa, ec, ed448, ed25519, rsa)
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


def analyze_chain(ders: list) -> "ChainInfo":
    """Analyze a leaf-first list of DER certificates as a presented chain."""
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
    return ch
