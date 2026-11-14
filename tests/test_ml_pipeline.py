import unittest
from src.ml.feature_extractor import BGPFeatureExtractor
from src.ml.pipeline import AnomalyMLPipeline
from src.core.rpki_validator import RPKIValidator
from src.core.explainability import ExplainabilityEngine

class TestMLPipelineAndExplainability(unittest.TestCase):
    def setUp(self):
        self.roas = [
            {"prefix": "1.1.1.0/24", "max_length": 24, "asn": 13335, "tai": "APNIC"},
            {"prefix": "93.184.216.0/20", "max_length": 20, "asn": 15133, "tai": "RIPE NCC"}
        ]
        self.validator = RPKIValidator(self.roas)
        self.ml_pipeline = AnomalyMLPipeline()

    def test_feature_extractor(self):
        update = {
            "prefix": "1.1.1.0/24",
            "origin_asn": 13335,
            "as_path": "3356 1299 13335",
            "as_path_len": 3,
            "rpki_state": "VALID",
            "is_bogon": 0
        }
        features = BGPFeatureExtractor.extract(update)
        self.assertEqual(len(features), 10)
        self.assertEqual(features[0], 3.0)  # path len
        self.assertEqual(features[4], 1.0)  # state valid

    def test_unexpected_origin_high_threat(self):
        update = {
            "prefix": "1.1.1.0/24",
            "origin_asn": 64512,  # Unauthorized origin
            "as_path": "3356 64512",
            "as_path_len": 2,
            "rpki_state": "INVALID_ASN",
            "is_bogon": 0
        }
        val_res = self.validator.validate(update["prefix"], update["origin_asn"])
        eval_res = self.ml_pipeline.evaluate(update, val_res)

        # Threat score should be high/critical
        self.assertGreaterEqual(eval_res.threat_score, 70.0)
        self.assertIn(eval_res.severity, ["HIGH", "CRITICAL"])

        # Explainability
        dossier = ExplainabilityEngine.generate(update, val_res, eval_res)
        self.assertEqual(dossier.anomaly_category, "UNEXPECTED_ORIGIN")
        self.assertIn("Unexpected Origin", dossier.summary)
        self.assertIn("AS13335", dossier.summary)

    def test_subprefix_hijack_critical(self):
        update = {
            "prefix": "93.184.216.0/24",  # Max length in ROA is 20
            "origin_asn": 15133,
            "as_path": "174 15133",
            "as_path_len": 2,
            "rpki_state": "INVALID_LENGTH",
            "is_bogon": 0
        }
        val_res = self.validator.validate(update["prefix"], update["origin_asn"])
        eval_res = self.ml_pipeline.evaluate(update, val_res)

        self.assertGreaterEqual(eval_res.threat_score, 75.0)
        dossier = ExplainabilityEngine.generate(update, val_res, eval_res)
        self.assertEqual(dossier.anomaly_category, "SUBPREFIX_HIJACK")
        self.assertIn("Subprefix Hijack", dossier.summary)

    def test_hitl_feedback_retraining(self):
        feedback = [
            {
                "operator_label": "FALSE_POSITIVE",
                "as_path": "3356 1299 15133",
                "as_path_len": 3,
                "prefix": "93.184.216.0/24",
                "rpki_state": "INVALID_LENGTH",
                "anomaly_type": "SUBPREFIX_HIJACK"
            }
        ]
        retrain_res = self.ml_pipeline.retrain_hitl(feedback)
        self.assertEqual(retrain_res["status"], "retrained_successfully")
        self.assertIn("samples_trained", retrain_res)

if __name__ == "__main__":
    unittest.main()
