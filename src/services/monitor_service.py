import json
import time
from typing import Any, Dict, List, Optional
from src.config import DATA_DIR
from src.db.connection import get_connection, init_db
from src.db.queries import (
    insert_bgp_update, insert_anomaly_alert, insert_roas,
    get_all_roas, get_operator_feedback, record_telemetry
)
from src.core.rpki_validator import RPKIValidator, RFC6811State
from src.core.bogon_filter import BogonFilter
from src.ml.pipeline import AnomalyMLPipeline
from src.core.explainability import ExplainabilityEngine

class BGPMonitorService:
    """Master orchestrator for BGP stream ingestion, RFC 6811 validation,

    machine learning scoring, explainability generation, and HITL feedback loop.
    """

    _instance: Optional["BGPMonitorService"] = None

    def __init__(self):
        init_db()
        self.validator = RPKIValidator()
        self.ml_pipeline = AnomalyMLPipeline()
        self._ensure_roas_loaded()

    @classmethod
    def get_instance(cls) -> "BGPMonitorService":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _ensure_roas_loaded(self) -> None:
        """Loads ROAs from database or seeds from data/roas_real_world.json."""
        existing = get_all_roas()
        if not existing:
            real_file = DATA_DIR / "roas_real_world.json"
            sample_file = DATA_DIR / "roas_sample.json"
            target_file = real_file if real_file.exists() else sample_file
            if target_file.exists():
                with open(target_file, "r") as f:
                    roas = json.load(f)
                insert_roas(roas)
                existing = get_all_roas()
        self.validator.load_roas(existing)

    def reload_roas(self) -> int:
        self._ensure_roas_loaded()
        roas = get_all_roas()
        return self.validator.load_roas(roas)

    def process_update(self, update: Dict[str, Any], conn: Optional[Any] = None) -> Dict[str, Any]:
        """Ingests and evaluates a single BGP update.
        Guarantees strict RFC 6811 validation, ML scoring, and transparent explanation.
        """
        start_time = time.perf_counter()

        # Step 1: Bogon & Reserved ASN / Prefix checks
        bogon_asns = BogonFilter.check_as_path_bogons(update.get("as_path", ""))
        is_bogon_prefix, prefix_reason = BogonFilter.is_bogon_prefix(update.get("prefix", ""))
        is_bogon = bool(bogon_asns or is_bogon_prefix)
        update["is_bogon"] = 1 if is_bogon else 0

        # Step 2: RFC 6811 Origin Validation
        val_result = self.validator.validate(update["prefix"], int(update["origin_asn"]))
        update["rpki_state"] = val_result.state.value

        # Step 3: Insert into BGP Updates Stream
        should_close = False
        if conn is None:
            conn = get_connection()
            should_close = True

        update_id = insert_bgp_update(update, conn)

        # Step 4: Machine Learning Layer (Isolation Forest + HITL Random Forest)
        ml_eval = self.ml_pipeline.evaluate(update, val_result)

        # Step 5: Decision Logic & Anomaly Alert Generation
        alert_id = None
        dossier = None
        should_alert = (
            is_bogon or
            val_result.rfc_state == "INVALID" or
            ml_eval.threat_score >= 38.0 or
            ml_eval.path_spike_flag
        )

        if should_alert:
            dossier = ExplainabilityEngine.generate(
                update=update,
                val_result=val_result,
                ml_eval=ml_eval,
                bogon_info=bogon_asns if bogon_asns else ([("Prefix", prefix_reason)] if is_bogon_prefix else None)
            )

            # Determine RFC verdict
            rule_verdict = "BOGON" if is_bogon else val_result.state.value

            alert_payload = {
                "update_id": update_id,
                "timestamp": update["timestamp"],
                "prefix": update["prefix"],
                "origin_asn": update["origin_asn"],
                "expected_asn": val_result.expected_asns,
                "anomaly_type": dossier.anomaly_category,
                "severity": ml_eval.severity,
                "rule_verdict": rule_verdict,
                "ml_anomaly_score": ml_eval.if_score,
                "rf_confidence": ml_eval.rf_confidence,
                "threat_score": ml_eval.threat_score,
                "explainability_summary": dossier.summary,
                "evidence_json": dossier.evidence_breakdown,
                "status": "PENDING_REVIEW"
            }
            alert_id = insert_anomaly_alert(alert_payload, conn)

        if should_close:
            conn.close()

        latency_ms = (time.perf_counter() - start_time) * 1000.0

        return {
            "update_id": update_id,
            "alert_id": alert_id,
            "rpki_state": val_result.state.value,
            "threat_score": ml_eval.threat_score,
            "severity": ml_eval.severity,
            "latency_ms": round(latency_ms, 3),
            "dossier": dossier
        }

    def process_batch(self, batch: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Processes a batch of updates and records telemetry performance."""
        results = []
        alerts_triggered = 0
        total_latency = 0.0

        tp = 0
        fp = 0
        fn = 0
        tn = 0

        conn = get_connection()
        try:
            for item in batch:
                res = self.process_update(item, conn=conn)
                results.append(res)
                total_latency += res["latency_ms"]

                is_alert = res["alert_id"] is not None
                if is_alert:
                    alerts_triggered += 1

                # If ground truth label is present in synthetic item, track evaluation metrics
                gt = item.get("ground_truth_label")
                if gt:
                    if gt == "MALICIOUS":
                        if is_alert:
                            tp += 1
                        else:
                            fn += 1
                    else:  # BENIGN
                        if is_alert:
                            fp += 1
                        else:
                            tn += 1
        finally:
            conn.close()

        avg_latency = (total_latency / len(batch)) if batch else 0.0

        # Calculate metrics if ground truth was available
        precision = (tp / (tp + fp)) if (tp + fp) > 0 else 1.0
        recall = (tp / (tp + fn)) if (tp + fn) > 0 else 1.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 1.0
        fpr = (fp / (fp + tn)) if (fp + tn) > 0 else 0.0

        telemetry = {
            "updates_processed": len(batch),
            "alerts_triggered": alerts_triggered,
            "avg_latency_ms": round(avg_latency, 3),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
            "false_positive_rate": round(fpr, 4)
        }
        record_telemetry(telemetry)

        return {
            "summary": telemetry,
            "results": results
        }

    def retrain_from_operator_feedback(self) -> Dict[str, Any]:
        """Fetches all human decisions from SQLite and updates the Random Forest model."""
        feedback = get_operator_feedback()
        return self.ml_pipeline.retrain_hitl(feedback)
