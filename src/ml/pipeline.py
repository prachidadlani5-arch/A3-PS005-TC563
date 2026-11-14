from dataclasses import dataclass
from typing import Any, Dict, List, Optional
import numpy as np
from src.ml.feature_extractor import BGPFeatureExtractor
from src.ml.isolation_forest import BGPIsolationForest
from src.ml.hitl_classifier import HITLRandomForest
from src.config import (
    SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO,
    WEIGHT_RULE_RFC6811, WEIGHT_ISOLATION_FOREST, WEIGHT_RANDOM_FOREST
)

@dataclass
class AnomalyEvaluation:
    rule_score: float
    if_score: float
    rf_confidence: float
    threat_score: float
    severity: str
    path_spike_flag: bool
    feature_vector: np.ndarray

class AnomalyMLPipeline:
    """Unified Machine Learning pipeline combining deterministic rule scores,

    unsupervised Isolation Forest outlier detection, and supervised HITL Random Forest.
    """

    def __init__(self):
        self.isolation_forest = BGPIsolationForest()
        self.hitl_rf = HITLRandomForest()

    def evaluate(self, update: Dict[str, Any], validation_result: Optional[Any] = None) -> AnomalyEvaluation:
        """Evaluates a BGP update and outputs calibrated scores and severity."""
        features = BGPFeatureExtractor.extract(update, validation_result)

        # 1. Deterministic Rule Score [0.0 - 1.0]
        if validation_result:
            if hasattr(validation_result, "state"):
                st = validation_result.state
                rpki_state = st.value if hasattr(st, "value") else str(st)
            else:
                rpki_state = str(getattr(validation_result, "rfc_state", "NOT_FOUND"))
        else:
            rpki_state = update.get("rpki_state", "NOT_FOUND")

        is_bogon = update.get("is_bogon", 0)

        if is_bogon:
            rule_score = 1.0
        elif rpki_state in ("INVALID_LENGTH", "INVALID_BOTH"):
            rule_score = 1.0   # RFC 6811 Invalid-Length is definitive hijack vector
        elif rpki_state == "INVALID_ASN":
            rule_score = 0.96  # Unexpected origin
        elif rpki_state == "NOT_FOUND":
            rule_score = 0.20  # Baseline unknown, depends on ML path behavior
        else:
            rule_score = 0.05  # Valid ROA

        # 2. Unsupervised Isolation Forest Score [0.0 - 1.0]
        if_score = self.isolation_forest.score(features)

        # 3. Supervised HITL Random Forest Confidence [0.0 - 1.0]
        rf_confidence = self.hitl_rf.predict_probability(features)

        # 4. Composite Threat Score [0.0 - 100.0]
        composite = (
            (WEIGHT_RULE_RFC6811 * rule_score) +
            (WEIGHT_ISOLATION_FOREST * if_score) +
            (WEIGHT_RANDOM_FOREST * rf_confidence)
        ) * 100.0
        threat_score = float(np.clip(composite, 0.0, 100.0))

        # Path spike flag
        path_len = features[0]
        path_spike_flag = bool(path_len >= 8 or features[9] >= 0.75)

        # 5. Severity assignment
        if threat_score >= 78.0:
            severity = SEVERITY_CRITICAL
        elif threat_score >= 55.0:
            severity = SEVERITY_HIGH
        elif threat_score >= 35.0:
            severity = SEVERITY_MEDIUM
        elif threat_score >= 18.0:
            severity = SEVERITY_LOW
        else:
            severity = SEVERITY_INFO

        return AnomalyEvaluation(
            rule_score=round(rule_score, 4),
            if_score=round(if_score, 4),
            rf_confidence=round(rf_confidence, 4),
            threat_score=round(threat_score, 1),
            severity=severity,
            path_spike_flag=path_spike_flag,
            feature_vector=features
        )

    def retrain_hitl(self, feedback_records: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Triggers dynamic retraining with new human operator feedback."""
        return self.hitl_rf.retrain(feedback_records)
