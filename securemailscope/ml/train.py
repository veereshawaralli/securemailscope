"""Train and persist the risk model from synthetic data. Requires scikit-learn;
if it is missing the analyzer still runs (rule-based fallback), so training is
optional. Invoked via `python -m securemailscope train` or the CLI.
"""
from __future__ import annotations

import os


def train(out: str | None = None, n: int = 4000, seed: int = 7) -> int:
    try:
        import numpy as np
        from sklearn.ensemble import (IsolationForest,
                                       RandomForestClassifier)
    except Exception as e:       # pragma: no cover
        print(f"[train] scikit-learn/numpy not installed: {e}")
        print("[train] The analyzer will use the rule-based fallback instead.")
        return 1

    from .model import _DEFAULT, RiskModel
    from .synth import make_dataset

    X, y = make_dataset(n, seed)
    X = np.array(X, dtype=float)
    clf = RandomForestClassifier(n_estimators=140, random_state=seed,
                                 class_weight="balanced").fit(X, y)
    iso = IsolationForest(n_estimators=140, contamination=0.15,
                          random_state=seed).fit(X)

    out = out or _DEFAULT
    os.makedirs(os.path.dirname(out), exist_ok=True)
    RiskModel(clf, iso).save(out)
    print(f"[train] samples={n}  train_accuracy={clf.score(X, y):.3f}")
    print(f"[train] saved model -> {out}")
    return 0


if __name__ == "__main__":        # pragma: no cover
    raise SystemExit(train())
