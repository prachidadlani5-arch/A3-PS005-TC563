import numpy as np
if not hasattr(np, "long"):
    np.long = np.int_
if not hasattr(np, "ulong"):
    np.ulong = np.uint
from sklearn.ensemble import IsolationForest
from typing import Optional

class BGPIsolationForest:
    """Unsupervised Anomaly Detector using Isolation Forest.
    Detects unusual path prepending, abnormal subprefix depths, and routing outliers.
    """

    def __init__(self, contamination: float = 0.05, random_state: int = 42):
        self.model = IsolationForest(
            n_estimators=50,
            contamination=contamination,
            random_state=random_state,
            n_jobs=1
        )
        self.is_fitted = False
        self.fit(np.empty((0, 10)))

    def fit(self, X: np.ndarray) -> "BGPIsolationForest":
        """Fits the Isolation Forest model on feature matrix X."""
        if len(X) < 10:
            # Generate synthetic baseline if initial data is too sparse
            synth_baseline = np.random.normal(
                loc=[4.0, 1.0, 24.0, 0.0, 0.8, 0.2, 0.0, 0.0, 0.0, 0.2],
                scale=[1.0, 0.1, 2.0, 0.1, 0.2, 0.2, 0.05, 0.05, 0.01, 0.1],
                size=(100, 10)
            )
            synth_baseline = np.clip(synth_baseline, 0.0, None)
            X = np.vstack([X, synth_baseline]) if len(X) > 0 else synth_baseline

        self.model.fit(X)
        self.is_fitted = True
        return self

    def score(self, x: np.ndarray) -> float:
        """Computes an anomaly threat score in the range [0.0, 1.0].
        0.0 = completely normal, 1.0 = highly anomalous outlier.
        """
        if not self.is_fitted:
            # Default fallback if called before initial fitting
            path_len = x[0] if len(x) > 0 else 4.0
            return float(min(1.0, max(0.0, (path_len - 3.5) / 6.0)))

        x_reshaped = x.reshape(1, -1)
        # Decision function: typical values roughly in [-0.5, 0.5]
        raw_score = self.model.decision_function(x_reshaped)[0]
        # Invert and scale: raw_score < 0 is anomaly, raw_score > 0 is inlier
        # Sigmoidal or linear transformation into [0.0, 1.0]
        anomaly_score = 1.0 / (1.0 + np.exp(6.0 * raw_score))
        return float(np.clip(anomaly_score, 0.0, 1.0))

    def batch_score(self, X: np.ndarray) -> np.ndarray:
        if not self.is_fitted:
            self.fit(X)
        raw_scores = self.model.decision_function(X)
        scores = 1.0 / (1.0 + np.exp(6.0 * raw_scores))
        return np.clip(scores, 0.0, 1.0)
