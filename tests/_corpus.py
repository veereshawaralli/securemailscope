"""Shared synthetic-corpus fixture for the suite: generate the labeled PCAP
scenarios once into a temp dir and expose analysis helpers plus the ground-truth
posture table the end-to-end tests assert against. No credentials, no network.
"""
from __future__ import annotations

import os
import tempfile

from securemailscope.analysis.engine import analyze
from securemailscope.samples.generate import generate

_DIR: str | None = None


def corpus_dir() -> str:
    """Generate the scenario corpus once (module-cached) and return its dir."""
    global _DIR
    if _DIR is None:
        _DIR = tempfile.mkdtemp(prefix="sms-tests-")
        generate(_DIR)
    return _DIR


def pcap_path(name: str) -> str:
    """Absolute path of a scenario pcap by bare name (no extension needed)."""
    fn = name if name.endswith(".pcap") else name + ".pcap"
    return os.path.join(corpus_dir(), fn)


def analyze_named(name: str, ml=None):
    return analyze(pcap_path(name), ml=ml)


def single(name: str, ml=None):
    """Analyze a one-session scenario and return that lone SessionResult."""
    res = analyze_named(name, ml=ml)
    assert len(res.sessions) == 1, f"{name}: expected exactly one session"
    return res.sessions[0]


# ground truth: scenario -> (grade, score, top-finding id, must-contain ids)
EXPECTED = {
    "01_smtp_starttls_good": ("A", 100, "SMS-OK", {"SMS-OK"}),
    "02_smtp_cleartext_auth": ("F", 2, "SMS-AUTH-CLEARTEXT",
                               {"SMS-AUTH-CLEARTEXT", "SMS-TLS-ABSENT",
                                "SMS-NO-STARTTLS"}),
    "03_imap_legacy_tls10": ("F", 6, "SMS-CERT_EXPIRED",
                             {"SMS-CERT_EXPIRED", "SMS-WEAK_RSA_KEY",
                              "SMS-TLS-DEPRECATED", "SMS-SELF_SIGNED",
                              "SMS-CIPHER-NO_PFS", "SMS-CIPHER-CBC",
                              "SMS-CIPHER-SHA1_MAC"}),
    "04_pop3s_rc4": ("C", 78, "SMS-CIPHER-RC4", {"SMS-CIPHER-RC4"}),
    "05_smtps_tls12_strong": ("A", 100, "SMS-OK", {"SMS-OK"}),
    "06_imaps_tls13": ("A", 100, "SMS-CERT-ENCRYPTED",
                       {"SMS-CERT-ENCRYPTED", "SMS-TLS13"}),
    "07_smtp_starttls_stripped": ("F", 2, "SMS-AUTH-CLEARTEXT",
                                  {"SMS-AUTH-CLEARTEXT", "SMS-TLS-ABSENT",
                                   "SMS-STARTTLS-STRIPPED"}),
}

OVERALL_GRADE = "F"
OVERALL_SCORE = 23
SESSION_COUNT = 7
