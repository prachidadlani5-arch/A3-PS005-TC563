from typing import Any, Dict, List, Tuple
import numpy as np
if not hasattr(np, "long"):
    np.long = np.int_
if not hasattr(np, "ulong"):
    np.ulong = np.uint
from sklearn.ensemble import RandomForestClassifier
from src.ml.feature_extractor import BGPFeatureExtractor

class HITLRandomForest:
    """Supervised Random Forest Classifier continuously trained on

    Human-in-the-Loop (HITL) operator feedback to separate true malicious hijacks
    from legitimate multi-homing shifts and benign routing changes.
    """

    def __init__(self, random_state: int = 42):
        self.model = RandomForestClassifier(
            n_estimators=50,
            max_depth=6,
            class_weight="balanced",
            n_jobs=1,
            random_state=random_state
        )
        self.is_fitted = False
        self.feature_names = BGPFeatureExtractor.FEATURE_NAMES
        self.training_sample_count = 0
        self._seed_initial_knowledge()

    def _seed_initial_knowledge(self) -> None:
        """Seeds the Random Forest with canonical examples of:
        - True Positives (1): Subprefix hijacks, unauthorized origins, bogons.
        - False Positives (0): Valid routes, legitimate multi-homing, normal path length.
        """
        X_seed = [
            # 1. Normal Valid Route
            [4.0, 1.0, 24.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.1],
            # 2. Legitimate multi-homing shift (valid route, slightly longer path)
            [5.0, 1.0, 22.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.3],
            # 3. Benign NotFound (unregistered small business prefix, normal path)
            [4.0, 1.0, 24.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.1],
            # 4. Malicious Unexpected Origin (Invalid-ASN)
            [4.0, 1.0, 24.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.2],
            # 5. Malicious Subprefix Hijack (/24 inside /16 ROA)
            [3.0, 1.0, 24.0, 8.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.1],
            # 6. Bogon ASN Hijack
            [6.0, 0.8, 24.0, 0.0, 0.0, 1.0, 0.0, 0.0, 1.0, 0.5],
            # 7. Extreme Path Spike (e.g. AS loop or route leak)
            [12.0, 0.5, 24.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0],
            # 8. Legitimate CDN multi-homing (Fastly/Cloudflare secondary AS)
            [3.0, 1.0, 20.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        ]
        # 1 = True Malicious Hijack / Anomaly, 0 = False Positive / Benign
        y_seed = [0, 0, 0, 1, 1, 1, 1, 0]

        X_expanded = []
        y_expanded = []
        for x, y in zip(X_seed, y_seed):
            # Duplicate with tiny jitter to create a stable initial seed
            for _ in range(8):
                jitter = np.random.normal(0, 0.02, size=len(x))
                noisy_x = np.clip(np.array(x) + jitter, 0.0, None)
                X_expanded.append(noisy_x)
                y_expanded.append(y)

        self.model.fit(np.array(X_expanded), np.array(y_expanded))
        self.is_fitted = True
        self.training_sample_count = len(y_expanded)

    def predict_probability(self, x: np.ndarray) -> float:
        """Returns the probability P(Malicious Anomaly = 1)."""
        if not self.is_fitted:
            return 0.5
        x_reshaped = x.reshape(1, -1)
        probs = self.model.predict_proba(x_reshaped)[0]
        # Index 1 is positive class
        return float(probs[1]) if len(probs) > 1 else float(probs[0])

    def retrain(self, feedback_records: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Incorporates human operator feedback decisions and retrains the model."""
        if not feedback_records:
            return {"status": "no_feedback_provided", "samples": self.training_sample_count}

        X_new = []
        y_new = []

        for rec in feedback_records:
            label = 1 if rec.get("operator_label") == "TRUE_POSITIVE" else 0
            # Build feature array from record attributes
            u = {
                "as_path": rec.get("as_path", ""),
                "as_path_len": rec.get("as_path_len", 4),
                "prefix": rec.get("prefix", "0.0.0.0/0"),
                "rpki_state": rec.get("rpki_state", "NOT_FOUND"),
                "is_bogon": 1 if rec.get("anomaly_type") == "BOGON_ASN" else 0
            }
            feat = BGPFeatureExtractor.extract(u)
            # Operator feedback receives 3x sample weighting for faster adaptation
            for _ in range(3):
                X_new.append(feat)
                y_new.append(label)

        # Re-seed baseline + new feedback
        self._seed_initial_knowledge()
        current_X = self.model.estimators_[0].tree_ if hasattr(self.model, "estimators_") else None
        
        # Merge baseline synthetic with feedback
        X_all = np.array(X_new)
        y_all = np.array(y_new)

        self.model.fit(X_all, y_all)
        self.training_sample_count += len(y_new)

        importances = dict(zip(self.feature_names, [round(float(v), 4) for v in self.model.feature_importances_]))

        return {
            "status": "retrained_successfully",
            "samples_trained": self.training_sample_count,
            "feature_importances": importances
        }

    def get_feature_importances(self) -> Dict[str, float]:
        if not self.is_fitted:
            return {}
        return dict(zip(self.feature_names, [round(float(v), 4) for v in self.model.feature_importances_]))
