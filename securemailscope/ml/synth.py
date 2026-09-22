"""Synthetic labeled dataset generator for training the risk model. Sessions
are sampled from realistic feature distributions and labeled with the same
deterministic taxonomy the rules engine uses, so the classifier learns to
reproduce (and generalize) expert judgement while the anomaly detector learns
the density of "normal" sessions. No real traffic or credentials involved.
"""
from __future__ import annotations

import random

from ..analysis import features as F
from .model import _rule_based


def _sample(rng: random.Random) -> dict:
    tls = int(rng.random() > 0.12)
    implicit = int(tls and rng.random() > 0.5)
    starttls_offered = int(rng.random() > 0.4)
    starttls_used = int(tls and not implicit and starttls_offered
                        and rng.random() > 0.4)
    cleartext_auth = int((not tls or not implicit) and rng.random() > 0.72)
    version_ordinal = rng.choice([1, 2, 3, 3, 4, 5, 5, 5, 6, 6]) if tls else 0
    deprecated = int(version_ordinal in (1, 2, 3, 4))
    grade = rng.choice([0, 1, 1, 2, 3, 3, 4, 4, 4]) if tls else 0
    pfs = int(grade >= 3 and rng.random() > 0.3)
    aead = int(grade >= 3 and rng.random() > 0.2)
    cipher_bits = rng.choice([0, 40, 112, 128, 128, 256, 256]) if tls else 0
    rsa_bits = rng.choice([0, 512, 1024, 2048, 2048, 4096])
    weak_key = int(0 < rsa_bits < 2048)
    weak_sig = int(rng.random() > 0.85)
    cert_expired = int(rng.random() > 0.85)
    self_signed = int(rng.random() > 0.8)
    chain_incomplete = int(rng.random() > 0.8)
    cert_count = 0 if (not tls or version_ordinal == 6) \
        else rng.choice([1, 2, 3])
    return {
        "tls_present": tls, "implicit_tls": implicit,
        "starttls_offered": starttls_offered, "starttls_used": starttls_used,
        "cleartext_auth": cleartext_auth, "version_ordinal": version_ordinal,
        "deprecated_version": deprecated, "cipher_grade_ordinal": grade,
        "pfs": pfs, "aead": aead, "cipher_bits": cipher_bits,
        "rsa_key_bits": rsa_bits, "weak_key": weak_key, "weak_sig": weak_sig,
        "cert_expired": cert_expired, "cert_self_signed": self_signed,
        "chain_incomplete": chain_incomplete, "cert_count": cert_count,
    }


def make_dataset(n: int = 4000, seed: int = 7):
    """Return (X, y): feature-vector rows and their risk-label strings."""
    rng = random.Random(seed)
    X, y = [], []
    for _ in range(n):
        feats = _sample(rng)
        X.append(F.vector(feats))
        y.append(_rule_based(feats)["risk_label"])
    return X, y
