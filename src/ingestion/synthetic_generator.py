import datetime
import random
from typing import Any, Dict, List, Optional

class SyntheticBGPGenerator:
    """Generates realistic BGP routing updates including benign baseline traffic,

    legitimate multi-homing shifts, and labeled synthetic hijacks (origin, subprefix, bogon).
    """

    TRANSIT_ASNS = [3356, 1299, 2914, 174, 6939, 6453, 3257, 7018]
    PEER_ROUTERS = [
        ("195.66.225.1", 5459),   # LINX London
        ("198.32.176.1", 24115),  # Equinix Ashburn
        ("80.249.208.1", 1200),   # AMS-IX Amsterdam
        ("206.108.34.1", 10310)   # SIX Seattle
    ]

    BENIGN_PREFIXES = [
        ("1.1.1.0/24", 13335),
        ("1.0.0.0/24", 13335),
        ("8.8.8.0/24", 15169),
        ("8.8.4.0/24", 15169),
        ("9.9.9.0/24", 19281),
        ("151.101.0.0/16", 54113),
        ("52.94.0.0/16", 16509),
        ("20.0.0.0/11", 8075)
    ]

    NOT_FOUND_PREFIXES = [
        ("199.19.112.0/24", 394380),  # Valid prefix but no ROA in test dataset
        ("185.12.64.0/22", 4134),
        ("212.58.244.0/24", 2818),
        ("194.109.6.0/24", 3265)
    ]

    MULTIHOMED_PREFIXES = [
        # Authorized for AS64496 AND AS20000
        ("198.51.200.0/22", 64496, 20000)
    ]

    @classmethod
    def _build_path(cls, peer_asn: int, origin_asn: int, intermediate_hops: Optional[int] = None) -> List[int]:
        if intermediate_hops is None:
            intermediate_hops = random.randint(1, 3)
        hops = [peer_asn]
        selected_transits = random.sample(cls.TRANSIT_ASNS, min(intermediate_hops, len(cls.TRANSIT_ASNS)))
        hops.extend(selected_transits)
        hops.append(origin_asn)
        return hops

    @classmethod
    def generate_benign_valid(cls) -> Dict[str, Any]:
        """Generates a legitimate RFC 6811 Valid BGP update."""
        prefix, origin = random.choice(cls.BENIGN_PREFIXES)
        peer_ip, peer_asn = random.choice(cls.PEER_ROUTERS)
        path = cls._build_path(peer_asn, origin)
        return {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "peer_ip": peer_ip,
            "peer_asn": peer_asn,
            "prefix": prefix,
            "origin_asn": origin,
            "as_path": " ".join(map(str, path)),
            "as_path_len": len(path),
            "ground_truth_label": "BENIGN",
            "anomaly_scenario": "Valid ROA Origin",
            "is_synthetic": 1
        }

    @classmethod
    def generate_benign_not_found(cls) -> Dict[str, Any]:
        """Generates an unregistered route (NotFound), normal in the DFZ."""
        prefix, origin = random.choice(cls.NOT_FOUND_PREFIXES)
        peer_ip, peer_asn = random.choice(cls.PEER_ROUTERS)
        path = cls._build_path(peer_asn, origin)
        return {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "peer_ip": peer_ip,
            "peer_asn": peer_asn,
            "prefix": prefix,
            "origin_asn": origin,
            "as_path": " ".join(map(str, path)),
            "as_path_len": len(path),
            "ground_truth_label": "BENIGN",
            "anomaly_scenario": "Unregistered Prefix (NotFound)",
            "is_synthetic": 1
        }

    @classmethod
    def generate_benign_multihoming(cls) -> Dict[str, Any]:
        """Simulates a multi-homing failover / secondary ASN announcement (Benign)."""
        prefix, primary_asn, secondary_asn = random.choice(cls.MULTIHOMED_PREFIXES)
        chosen_asn = random.choice([primary_asn, secondary_asn])
        peer_ip, peer_asn = random.choice(cls.PEER_ROUTERS)
        path = cls._build_path(peer_asn, chosen_asn, intermediate_hops=3)
        return {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "peer_ip": peer_ip,
            "peer_asn": peer_asn,
            "prefix": prefix,
            "origin_asn": chosen_asn,
            "as_path": " ".join(map(str, path)),
            "as_path_len": len(path),
            "ground_truth_label": "BENIGN",
            "anomaly_scenario": "Legitimate Multi-Homing Failover",
            "is_synthetic": 1
        }

    @classmethod
    def generate_unexpected_origin_hijack(cls) -> Dict[str, Any]:
        """Malicious attacker announces a registered prefix with an unauthorized origin ASN."""
        victim_prefix, _ = random.choice(cls.BENIGN_PREFIXES)
        # Attacker ASN (e.g. Rogue ASN 99999 or 4837)
        attacker_asn = random.choice([99999, 4837, 58453, 20912])
        peer_ip, peer_asn = random.choice(cls.PEER_ROUTERS)
        path = cls._build_path(peer_asn, attacker_asn)
        return {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "peer_ip": peer_ip,
            "peer_asn": peer_asn,
            "prefix": victim_prefix,
            "origin_asn": attacker_asn,
            "as_path": " ".join(map(str, path)),
            "as_path_len": len(path),
            "ground_truth_label": "MALICIOUS",
            "anomaly_scenario": "Unauthorized Origin Hijack (Invalid-ASN)",
            "is_synthetic": 1
        }

    @classmethod
    def generate_subprefix_hijack(cls) -> Dict[str, Any]:
        """Subprefix hijack: announces a /24 within a /20 ROA whose max-length is /20."""
        # 93.184.216.0/20 authorized for AS15133 with max_length 20
        # Attacker or rogue entity announces 93.184.216.0/24 (Invalid-Length)
        peer_ip, peer_asn = random.choice(cls.PEER_ROUTERS)
        path = cls._build_path(peer_asn, 15133)
        return {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "peer_ip": peer_ip,
            "peer_asn": peer_asn,
            "prefix": "93.184.216.0/24",
            "origin_asn": 15133,
            "as_path": " ".join(map(str, path)),
            "as_path_len": len(path),
            "ground_truth_label": "MALICIOUS",
            "anomaly_scenario": "Subprefix Hijack (Invalid-Length /24 within /20)",
            "is_synthetic": 1
        }

    @classmethod
    def generate_bogon_hijack(cls) -> Dict[str, Any]:
        """Announces a route with a Private/Reserved ASN in the AS_PATH."""
        peer_ip, peer_asn = random.choice(cls.PEER_ROUTERS)
        private_asn = random.choice([64512, 65001, 65534])
        path = [peer_asn, 3356, private_asn, 13335]
        return {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "peer_ip": peer_ip,
            "peer_asn": peer_asn,
            "prefix": "1.1.1.0/24",
            "origin_asn": 13335,
            "as_path": " ".join(map(str, path)),
            "as_path_len": len(path),
            "ground_truth_label": "MALICIOUS",
            "anomaly_scenario": "Bogon / Private ASN Leak in AS_PATH",
            "is_synthetic": 1
        }

    @classmethod
    def generate_youtube_historical_hijack(cls) -> Dict[str, Any]:
        """Replay of the famous 2008 YouTube Hijack:

        ROA authorizes AS36561 for 208.65.152.0/22.
        Pakistan Telecom (AS17557) announced more-specific 208.65.153.0/24.
        """
        peer_ip, peer_asn = cls.PEER_ROUTERS[0]
        # Injected announcement by AS17557
        path = [peer_asn, 3356, 3491, 17557]
        return {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "peer_ip": peer_ip,
            "peer_asn": peer_asn,
            "prefix": "208.65.153.0/24",
            "origin_asn": 17557,
            "as_path": " ".join(map(str, path)),
            "as_path_len": len(path),
            "ground_truth_label": "MALICIOUS",
            "anomaly_scenario": "Historical YouTube 2008 Subprefix & Origin Hijack",
            "is_synthetic": 1
        }

    @classmethod
    def generate_stream_batch(cls, size: int = 20, anomaly_ratio: float = 0.2) -> List[Dict[str, Any]]:
        """Generates a realistic stream batch with a controlled percentage of anomalies."""
        batch = []
        num_anomalies = int(size * anomaly_ratio)
        num_benign = size - num_anomalies

        for _ in range(num_benign):
            r = random.random()
            if r < 0.60:
                batch.append(cls.generate_benign_valid())
            elif r < 0.85:
                batch.append(cls.generate_benign_not_found())
            else:
                batch.append(cls.generate_benign_multihoming())

        anomaly_generators = [
            cls.generate_unexpected_origin_hijack,
            cls.generate_subprefix_hijack,
            cls.generate_bogon_hijack,
            cls.generate_youtube_historical_hijack
        ]
        for _ in range(num_anomalies):
            gen = random.choice(anomaly_generators)
            batch.append(gen())

        random.shuffle(batch)
        return batch
