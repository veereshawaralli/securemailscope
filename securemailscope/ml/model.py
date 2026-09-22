"""Cryptographic risk model: a RandomForest risk classifier plus an
IsolationForest anomaly detector, loaded from disk when scikit-learn/joblib
and a trained artifact are available. When they are not, `predict` falls back
to a deterministic rule-based scorer so the pipeline always yields a result.
"""
from __future__ import annotations

import os

from ..analysis import features as F

try:
    import joblib
    _HAVE_JOBLIB = True
except Exception:            # pragma: no cover
    _HAVE_JOBLIB = False

_LABELS = ["minimal", "low", "medium", "high", "critical"]

_DEFAULT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "models", "riskmodel.joblib")


def _rule_based(feats: dict) -> dict:
    """Deterministic risk scoring mirroring the rules taxonomy (no ML needed)."""
    tls = feats.get("tls_present", 0)
    grade = feats.get("cipher_grade_ordinal", 2)
    ver = feats.get("version_ordinal", 0)
    if not tls or feats.get("cleartext_auth") or grade == 0 or ver in (1, 2):
        label = "critical"
    elif feats.get("cert_expired") or feats.get("weak_key") or ver in (3, 4) \
            or grade == 1:
        label = "high"
    elif (not feats.get("pfs")) or feats.get("cert_self_signed") \
            or feats.get("weak_sig"):
        label = "medium"
    elif grade == 3:
        label = "low"
    else:
        label = "minimal"
    anomaly = bool((tls and grade <= 1)
                   or (not tls and feats.get("starttls_offered"))
                   or feats.get("cleartext_auth"))
    return {"risk_label": label, "confidence": 0.6,
            "anomaly": anomaly, "anomaly_score": 0.8 if anomaly else 0.1,
            "source": "rules"}


class RiskModel:
    """Wraps the (optional) sklearn estimators; degrades to rule-based scoring."""

    def __init__(self, clf=None, iso=None, names=None):
        self.clf = clf
        self.iso = iso
        self.names = names or F.FEATURE_NAMES

    @property
    def ml_backed(self) -> bool:
        return self.clf is not None and self.iso is not None

    def predict(self, feats: dict) -> dict:
        if not self.ml_backed:
            return _rule_based(feats)
        try:
            import numpy as np
            x = np.array([[float(feats.get(n, 0)) for n in self.names]])
            label = str(self.clf.predict(x)[0])
            proba = float(max(self.clf.predict_proba(x)[0]))
            raw = float(self.iso.decision_function(x)[0])
            is_anom = int(self.iso.predict(x)[0]) == -1
        except Exception:            # pragma: no cover
            return _rule_based(feats)
        score = max(0.0, min(1.0, 0.5 - raw))
        return {"risk_label": label, "confidence": round(proba, 3),
                "anomaly": bool(is_anom), "anomaly_score": round(score, 3),
                "source": "ml"}

    def save(self, path: str) -> None:
        import joblib
        joblib.dump({"clf": self.clf, "iso": self.iso, "names": self.names},
                    path)

    @classmethod
    def load(cls, path: str) -> "RiskModel":
        import joblib
        d = joblib.load(path)
        return cls(d.get("clf"), d.get("iso"), d.get("names"))


def load_default(path: str | None = None) -> RiskModel:
    """Load the trained model if present, else a rule-based RiskModel."""
    p = path or _DEFAULT
    if _HAVE_JOBLIB and os.path.exists(p):
        try:
            return RiskModel.load(p)
        except Exception:        # pragma: no cover
            pass
    return RiskModel()
