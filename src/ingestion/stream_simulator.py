import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from src.services.monitor_service import BGPMonitorService
from src.ingestion.synthetic_generator import SyntheticBGPGenerator
from src.config import DATA_DIR

class BGPStreamSimulator:
    """Manages telemetry stream replay, live batch ingestion, and direct anomaly injection."""

    def __init__(self, service: Optional[BGPMonitorService] = None):
        self.service = service or BGPMonitorService.get_instance()

    def step(self) -> Dict[str, Any]:
        """Ingests a single random update (80% benign, 20% anomaly)."""
        batch = SyntheticBGPGenerator.generate_stream_batch(size=1, anomaly_ratio=0.20)
        res = self.service.process_update(batch[0])
        return res

    def step_batch(self, count: int = 10, anomaly_ratio: float = 0.20) -> Dict[str, Any]:
        """Ingests a batch of generated updates."""
        batch = SyntheticBGPGenerator.generate_stream_batch(size=count, anomaly_ratio=anomaly_ratio)
        return self.service.process_batch(batch)

    def inject_scenario(self, scenario_type: str) -> Dict[str, Any]:
        """Injects a specific labeled scenario directly into the active pipeline."""
        if scenario_type == "SUBPREFIX_HIJACK":
            item = SyntheticBGPGenerator.generate_subprefix_hijack()
        elif scenario_type == "UNEXPECTED_ORIGIN":
            item = SyntheticBGPGenerator.generate_unexpected_origin_hijack()
        elif scenario_type == "BOGON_ASN":
            item = SyntheticBGPGenerator.generate_bogon_hijack()
        elif scenario_type == "YOUTUBE_HISTORICAL":
            item = SyntheticBGPGenerator.generate_youtube_historical_hijack()
        elif scenario_type == "MULTIHOMING_FAILOVER":
            item = SyntheticBGPGenerator.generate_benign_multihoming()
        else:
            item = SyntheticBGPGenerator.generate_benign_valid()

        return self.service.process_update(item)

    def load_historical_sample(self, file_path: Optional[Path] = None) -> Dict[str, Any]:
        """Replays historical BGP update feed from JSON file."""
        if file_path is None:
            real_file = DATA_DIR / "bgp_updates_real_world.json"
            sample_file = DATA_DIR / "bgp_updates_sample.json"
            file_path = real_file if real_file.exists() else sample_file

        if not file_path.exists():
            return {"error": f"File {file_path} not found"}

        with open(file_path, "r") as f:
            updates = json.load(f)

        return self.service.process_batch(updates)

    def fetch_and_ingest_live_prefix(self, prefix_str: str, max_peers: int = 10) -> Dict[str, Any]:
        """Queries RIPE Looking Glass collectors live over the network and ingests the routes."""
        from src.ingestion.real_world_fetcher import RealWorldDataFetcher
        routes = RealWorldDataFetcher.fetch_real_bgp_routes_for_prefix(prefix_str, max_peers=max_peers)
        if not routes:
            return {"error": f"No routes found from RIPE Looking Glass for {prefix_str}", "count": 0}
        batch_res = self.service.process_batch(routes)
        return {"routes_ingested": len(routes), "summary": batch_res["summary"]}
