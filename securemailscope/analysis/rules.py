"""Deterministic rules engine: maps parsed TLS / certificate / protocol facts
to graded Findings with evidence, remediation and standards references. This
is the explainable backbone of the assessment; the ML layer only augments it.
"""
from __future__ import annotations

from .models import Finding, Severity

CRIT, HIGH, MED, LOW, INFO = (Severity.CRITICAL, Severity.HIGH,
                              Severity.MEDIUM, Severity.LOW, Severity.INFO)

# standards / advisory references
R_8996 = "RFC 8996 - Deprecating TLS 1.0/1.1"
R_8314 = "RFC 8314 - TLS for email submission and access"
R_7525 = "RFC 7525 / BCP 195 - Recommendations for secure use of TLS"
R_3207 = "RFC 3207 - SMTP Service Extension for Secure SMTP over TLS"
R_7465 = "RFC 7465 - Prohibiting RC4 cipher suites"
R_SWEET32 = "CVE-2016-2183 - SWEET32 birthday attack on 64-bit block ciphers"


def _f(fid, title, sev, cat, ev, rec, refs):
    return Finding(fid, title, sev, cat, ev, rec, list(refs))


# cipher issue-tag -> (severity, title, recommendation, refs)
_CIPHER_RULES = {
    "NULL_CIPHER":   (CRIT, "NULL cipher - no confidentiality",
                      "Disable all NULL cipher suites.", [R_7525]),
    "NO_ENCRYPTION": (CRIT, "Unencrypted cipher suite negotiated",
                      "Disable eNULL suites; require AEAD.", [R_7525]),
    "EXPORT":        (CRIT, "Export-grade cipher (FREAK/Logjam class)",
                      "Disable all EXPORT cipher suites.", [R_7525]),
    "RC4":           (HIGH, "RC4 stream cipher in use",
                      "Disable RC4 per RFC 7465.", [R_7465]),
    "MD5":           (HIGH, "MD5-based cipher suite",
                      "Disable MD5-MAC cipher suites.", [R_7525]),
    "3DES":          (MED,  "3DES 64-bit block cipher (SWEET32)",
                      "Disable 3DES; use AES-GCM or ChaCha20.", [R_SWEET32]),
    "NO_PFS":        (MED,  "No forward secrecy (static RSA key exchange)",
                      "Prefer ECDHE/DHE key exchange for PFS.", [R_7525]),
    "CBC":           (LOW,  "CBC-mode cipher (BEAST/Lucky13 class)",
                      "Prefer AEAD suites (GCM/ChaCha20).", [R_7525]),
    "SHA1_MAC":      (LOW,  "SHA-1 MAC in cipher suite",
                      "Prefer SHA-256+ or AEAD suites.", [R_7525]),
}
_CIPHER_ORDER = ["NULL_CIPHER", "NO_ENCRYPTION", "EXPORT", "RC4", "MD5",
                 "3DES", "NO_PFS", "CBC", "SHA1_MAC"]

# certificate weakness-tag -> (severity, title, recommendation, refs)
_CERT_RULES = {
    "VERY_WEAK_RSA_KEY": (CRIT, "RSA key smaller than 1024 bits",
                          "Reissue with RSA >= 2048 or ECDSA P-256.", [R_7525]),
    "WEAK_RSA_KEY":      (HIGH, "RSA key smaller than 2048 bits",
                          "Reissue with RSA >= 2048 or ECDSA P-256.", [R_7525]),
    "WEAK_EC_KEY":       (HIGH, "EC key smaller than 256 bits",
                          "Use a curve of at least P-256.", [R_7525]),
    "DSA_KEY":           (MED,  "DSA certificate key",
                          "Migrate to RSA >= 2048 or ECDSA.", [R_7525]),
    "MD5_SIG":           (CRIT, "Certificate signed with MD5",
                          "Reissue with a SHA-256+ signature.", [R_7525]),
    "SHA1_SIG":          (HIGH, "Certificate signed with SHA-1",
                          "Reissue with a SHA-256+ signature.", [R_7525]),
    "CERT_EXPIRED":      (HIGH, "Server certificate has expired",
                          "Renew the certificate immediately.", []),
    "CERT_NOT_YET_VALID": (MED, "Certificate is not yet valid",
                           "Check server clock and issuance window.", []),
    "CERT_EXPIRING_SOON": (LOW, "Certificate expires within 30 days",
                           "Renew before expiry to avoid outages.", []),
    "SELF_SIGNED":       (MED,  "Self-signed certificate",
                          "Use a CA-issued certificate for public services.", []),
    "CHAIN_INCOMPLETE":  (LOW,  "Incomplete certificate chain",
                          "Serve the full intermediate chain.", []),
    "CHAIN_SIGNATURE_INVALID": (HIGH, "Certificate chain signature failed to verify",
                          "Investigate the presented chain; a certificate is not "
                          "validly signed by its issuer (possible "
                          "misconfiguration, corruption or interception).", [R_7525]),
    "CERT_PARSE_ERROR":  (MED,  "Certificate could not be parsed",
                          "Verify the presented DER is well-formed.", []),
    "CERT_NOT_ANALYZED": (INFO, "Certificate not analyzed",
                          "Install `cryptography` for full certificate checks.", []),
}


def _protocol_findings(s, out):
    proto, port = s.get("protocol", "?"), s.get("server_port")
    if s.get("cleartext_auth"):
        out.append(_f(
            "SMS-AUTH-CLEARTEXT", "Credentials transmitted in cleartext", CRIT,
            "protocol",
            f"{proto} authentication bytes observed before encryption on "
            f"port {port}.",
            "Never accept AUTH/USER/PASS before TLS; require implicit TLS or "
            "a completed STARTTLS upgrade.", [R_8314, R_3207]))
    if not s.get("tls_present"):
        out.append(_f(
            "SMS-TLS-ABSENT", "No transport encryption on email session", CRIT,
            "tls", f"{proto} session on port {port} carried entirely in "
            "cleartext; no TLS handshake seen.",
            "Enable implicit TLS (465/993/995) or enforce STARTTLS.", [R_8314]))
        if s.get("starttls_offered"):
            out.append(_f(
                "SMS-STARTTLS-STRIPPED", "STARTTLS advertised but never used",
                HIGH, "protocol",
                "Server advertised STARTTLS/STLS but the session stayed "
                "cleartext - possible downgrade/stripping.",
                "Enforce STARTTLS and alert on plaintext sessions following a "
                "STARTTLS offer.", [R_3207, R_8314]))
        elif port in (25, 143, 110):
            out.append(_f(
                "SMS-NO-STARTTLS", "No STARTTLS capability offered", HIGH,
                "protocol",
                f"No STARTTLS/STLS advertised on cleartext port {port}.",
                "Deploy a certificate and advertise STARTTLS, or migrate to "
                "implicit TLS.", [R_8314]))


def _version_findings(s, out):
    if not s.get("tls_present"):
        return
    v = s.get("negotiated_version_name") or "unknown"
    if v in ("SSL 2.0", "SSL 3.0"):
        out.append(_f(
            "SMS-SSL-OBSOLETE", f"Obsolete {v} negotiated", CRIT, "tls-version",
            f"Server negotiated {v}, which is cryptographically broken "
            "(POODLE / DROWN).", "Disable SSLv2 and SSLv3 entirely.",
            [R_8996, R_7525]))
    elif v in ("TLS 1.0", "TLS 1.1"):
        out.append(_f(
            "SMS-TLS-DEPRECATED", f"Deprecated {v} negotiated", HIGH,
            "tls-version",
            f"Server negotiated {v}, deprecated by RFC 8996.",
            "Require TLS 1.2 or higher; prefer TLS 1.3.", [R_8996, R_7525]))
    elif v == "TLS 1.3":
        out.append(_f(
            "SMS-TLS13", "Modern TLS 1.3 negotiated", INFO, "tls-version",
            "Session negotiated TLS 1.3.", "No action required.", []))


def _cipher_findings(s, out):
    if not s.get("tls_present"):
        return
    issues = set(s.get("cipher_issues", []))
    cname = s.get("cipher_suite_name", "")
    for tag in _CIPHER_ORDER:
        if tag in issues:
            sev, title, rec, refs = _CIPHER_RULES[tag]
            out.append(_f(
                f"SMS-CIPHER-{tag}", title, sev, "cipher",
                f"Negotiated suite {cname} carries weakness: {tag}.",
                rec, refs))
    if "UNKNOWN_SUITE" in issues:
        out.append(_f(
            "SMS-CIPHER-UNKNOWN", "Unrecognized cipher suite", LOW, "cipher",
            f"Suite {cname} is not in the known registry; strength cannot be "
            "verified.",
            "Verify the suite against the IANA registry and disable if "
            "non-compliant.", [R_7525]))


def _cert_findings(s, chain, out):
    if not chain or chain.get("count", 0) == 0:
        if s.get("tls_present") and s.get("negotiated_version_name") == "TLS 1.3":
            out.append(_f(
                "SMS-CERT-ENCRYPTED", "Certificate encrypted (TLS 1.3)", INFO,
                "certificate",
                "TLS 1.3 encrypts the Certificate message, so passive "
                "extraction is not possible for this session.",
                "Use active probing (e.g. testssl.sh) to inspect the TLS 1.3 "
                "certificate.", []))
        return
    leaf = chain.get("leaf") or {}
    subj = leaf.get("subject", "") or "unknown subject"
    for tag in leaf.get("weaknesses", []):
        rule = _CERT_RULES.get(tag)
        if not rule:
            continue
        sev, title, rec, refs = rule
        detail = f"Leaf certificate ({subj}): {tag}"
        if tag.startswith("CERT_EXP"):
            detail += f"; not_after={leaf.get('not_after', '')}"
        out.append(_f(f"SMS-{tag}", title, sev, "certificate", detail, rec, refs))


def evaluate(summary: dict, chain: dict | None = None) -> list:
    """Run every rule group and return findings sorted most-severe first."""
    out: list = []
    _protocol_findings(summary, out)
    _version_findings(summary, out)
    _cipher_findings(summary, out)
    _cert_findings(summary, chain or {}, out)
    if not out:
        out.append(_f(
            "SMS-OK", "No cryptographic weaknesses detected", INFO, "summary",
            "Session negotiated modern TLS with a strong cipher and a valid "
            "certificate.",
            "Maintain the current configuration and keep certificates "
            "renewed.", []))
    out.sort(key=lambda f: (-int(f.severity), f.category, f.id))
    return out
