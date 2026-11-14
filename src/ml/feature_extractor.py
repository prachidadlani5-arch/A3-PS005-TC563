import ipaddress
from typing import Any, Dict, List, Optional
import numpy as np

class BGPFeatureExtractor:
    """Extracts normalized numerical features from BGP updates and validation states

    for consumption by Isolation Forest and Random Forest classifiers.
    """

    FEATURE_NAMES = [
        "as_path_len",
        "unique_as_ratio",
        "prefix_len",
        "subprefix_depth",
        "rpki_state_valid",
        "rpki_state_not_found",
        "rpki_state_invalid_asn",
        "rpki_state_invalid_len",
        "is_bogon",
        "path_spike_score"
    ]

    BASELINE_AVG_PATH_LEN = 3.8
    BASELINE_STD_PATH_LEN = 1.4

    @classmethod
    def extract(cls, update: Dict[str, Any], validation_result: Optional[Any] = None) -> np.ndarray:
        """Extracts a 1D feature array from an update dictionary and its validation result."""
        # 1. AS Path parsing
        as_path_str = str(update.get("as_path", ""))
        hops = [int(x) for x in as_path_str.split() if x.isdigit()]
        path_len = len(hops) if hops else int(update.get("as_path_len", 1))
        unique_hops = len(set(hops)) if hops else path_len
        unique_ratio = (unique_hops / path_len) if path_len > 0 else 1.0

        # 2. Prefix length
        prefix_str = update.get("prefix", "0.0.0.0/0")
        try:
            net = ipaddress.ip_network(prefix_str, strict=False)
            prefix_len = net.prefixlen
        except ValueError:
            prefix_len = 24

        # 3. Subprefix depth against ROA max_length
        subprefix_depth = 0
        if validation_result and hasattr(validation_result, "max_lengths") and validation_result.max_lengths:
            max_len = max(validation_result.max_lengths)
            subprefix_depth = max(0, prefix_len - max_len)

        # 4. RFC 6811 State One-Hot
        if validation_result:
            if hasattr(validation_result, "state"):
                st = validation_result.state
                rpki_state = st.value if hasattr(st, "value") else str(st)
            else:
                rpki_state = str(getattr(validation_result, "rfc_state", "NOT_FOUND"))
        else:
            rpki_state = update.get("rpki_state", "NOT_FOUND")

        state_valid = 1.0 if rpki_state == "VALID" else 0.0
        state_not_found = 1.0 if rpki_state == "NOT_FOUND" else 0.0
        state_inv_asn = 1.0 if rpki_state in ("INVALID_ASN", "INVALID_BOTH") else 0.0
        state_inv_len = 1.0 if rpki_state in ("INVALID_LENGTH", "INVALID_BOTH") else 0.0

        # 5. Bogon indicator
        is_bogon = 1.0 if update.get("is_bogon", 0) else 0.0

        # 6. Path spike metric (z-score against standard Internet BGP path statistics)
        z_score = max(0.0, (path_len - cls.BASELINE_AVG_PATH_LEN) / cls.BASELINE_STD_PATH_LEN)
        path_spike_score = min(3.0, z_score) / 3.0  # Normalized [0, 1]

        features = [
            float(path_len),
            float(unique_ratio),
            float(prefix_len),
            float(subprefix_depth),
            state_valid,
            state_not_found,
            state_inv_asn,
            state_inv_len,
            is_bogon,
            float(path_spike_score)
        ]

        return np.array(features, dtype=np.float32)

    @classmethod
    def batch_extract(cls, updates: List[Dict[str, Any]], val_results: Optional[List[Any]] = None) -> np.ndarray:
        matrix = []
        for i, u in enumerate(updates):
            vr = val_results[i] if val_results and i < len(val_results) else None
            matrix.append(cls.extract(u, vr))
        return np.array(matrix, dtype=np.float32)
