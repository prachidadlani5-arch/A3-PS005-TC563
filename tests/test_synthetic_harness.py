import unittest
from src.services.monitor_service import BGPMonitorService
from src.ingestion.synthetic_generator import SyntheticBGPGenerator
from src.db.connection import reset_db

class TestSyntheticEvaluationHarness(unittest.TestCase):
    def setUp(self):
        reset_db()
        self.service = BGPMonitorService.get_instance()
        self.service.reload_roas()

    def test_single_subprefix_injection(self):
        item = SyntheticBGPGenerator.generate_subprefix_hijack()
        res = self.service.process_update(item)
        self.assertIsNotNone(res["alert_id"])
        self.assertEqual(res["rpki_state"], "INVALID_LENGTH")
        self.assertGreaterEqual(res["threat_score"], 70.0)
        self.assertLess(res["latency_ms"], 100.0, f"Latency {res['latency_ms']}ms exceeded 100ms tolerance")

    def test_single_origin_hijack(self):
        item = SyntheticBGPGenerator.generate_unexpected_origin_hijack()
        res = self.service.process_update(item)
        self.assertIsNotNone(res["alert_id"])
        self.assertEqual(res["rpki_state"], "INVALID_ASN")
        self.assertGreaterEqual(res["threat_score"], 60.0)

    def test_single_bogon_injection(self):
        item = SyntheticBGPGenerator.generate_bogon_hijack()
        res = self.service.process_update(item)
        self.assertIsNotNone(res["alert_id"])
        self.assertIn("BOGON", res["dossier"].anomaly_category)

    def test_youtube_historical_hijack_replay(self):
        item = SyntheticBGPGenerator.generate_youtube_historical_hijack()
        res = self.service.process_update(item)
        self.assertIsNotNone(res["alert_id"])
        # YouTube 208.65.152.0/22 max-len 22 announced as 208.65.153.0/24 by AS17557
        self.assertIn("INVALID", res["rpki_state"])

    def test_batch_synthetic_evaluation_metrics(self):
        batch = SyntheticBGPGenerator.generate_stream_batch(size=30, anomaly_ratio=0.3)
        res = self.service.process_batch(batch)
        summary = res["summary"]

        print("\n--- Synthetic Evaluation Benchmark Results ---")
        print(f"Total Updates Processed: {summary['updates_processed']}")
        print(f"Alerts Triggered:        {summary['alerts_triggered']}")
        print(f"Average Latency:         {summary['avg_latency_ms']} ms (Target: < 50ms)")
        print(f"Precision:               {summary['precision']:.4f}")
        print(f"Recall:                  {summary['recall']:.4f}")
        print(f"F1-Score:                {summary['f1_score']:.4f}")
        print(f"False Positive Rate:     {summary['false_positive_rate']:.4f}")

        self.assertGreaterEqual(summary["recall"], 0.90)
        self.assertLess(summary["avg_latency_ms"], 50.0)

if __name__ == "__main__":
    unittest.main()
