# AIORI-3 Hackathon (Team TC-563)
## Explainable BGP Origin and Subprefix Anomaly Monitor

**AIORI Hackathon 2026** — *Problem Statement PS-005: Explainable BGP Origin and Subprefix Anomaly Monitor*  
**Team Code**: TC-563 (A3-PS005-TC563)  
**Standard Compliance**: RFC 6811 (BGP Prefix Origin Validation), RFC 5398 / 6996 / 7300 (Bogon ASNs)  
**Security Posture**: Strictly Passive Watchdog (No automated route blackholing or disruptive action)  

---

## 🚀 Key Features

1. **Deterministic RFC 6811 Validation Engine (`src/core/rpki_validator.py`)**:
   - Custom bitwise `PrefixTrie` (Radix Tree) providing $O(k)$ longest and covering prefix lookups.
   - Evaluates routes against RPKI Route Origin Authorizations (ROAs):
     - `VALID`: Prefix length $\le$ `max_length` and origin ASN matches ROA.
     - `NOT_FOUND`: No covering ROA exists in the RPKI cache.
     - `INVALID_ASN`: ROA exists but announcing origin ASN is unauthorized.
     - `INVALID_LENGTH`: Announced prefix is more specific than authorized `max_length` (Subprefix Hijack).

2. **Bogon & Private ASN Filter (`src/core/bogon_filter.py`)**:
   - Detects 16-bit and 32-bit reserved/private ASNs (RFC 6996, RFC 7300, RFC 5398) leaked in the public DFZ.
   - Identifies Bogon IPv4/IPv6 address blocks (RFC 1918, RFC 6598).

3. **Adaptive ML Layer (`src/ml/`)**:
   - **Unsupervised Anomaly Detection (`BGPIsolationForest`)**: Identifies path length anomalies and routing churn.
   - **Continuous Supervised Learning (`HITLRandomForest`)**: Continuously adapts based on operator feedback to distinguish true hijacks from benign multi-homing failovers.
   - **Calibrated Threat Score [0 - 100]**: Blends deterministic rule priority with ML anomaly probabilities.

4. **Transparent Explainability Engine (`src/core/explainability.py`)**:
   - Generates human-auditable evidence dossiers showing exact ROA rules, AS_PATH hops, and attribution scores.
   - Includes passive mitigation advisories.

5. **Streamlit SOC Dashboard (`app.py`)**:
   - Real-time telemetry feed inspector.
   - Human-in-the-Loop review queue with 1-click confirmation (`True Positive` / `False Positive`) and instant model retraining.
   - Hackathon benchmark suite (Precision, Recall, F1, Latency gauge, Confusion Matrix).
   - Interactive RPKI ROA sandbox.
   - Live BGP Route Inspector with interactive Plotly AS_PATH visual graph.

---

## 📁 Repository Structure

```
.
├── app.py                            # Streamlit SOC Dashboard entry point
├── requirements.txt                  # Python dependencies
├── implementation_plan.md            # Technical architecture & assembly spec
├── Proposed-structure-hackathon.pdf  # Hackathon proposal document
├── data/
│   ├── roas_real_world.json          # 182 Real-World Production ROAs (APNIC, ARIN, RIPE NCC)
│   ├── bgp_updates_real_world.json   # Real-world BGP feeds from RIPE Looking Glass collectors
│   ├── roas_sample.json              # Baseline sample ROAs
│   └── bgp_updates_sample.json       # Baseline sample updates
├── src/
│   ├── config.py                     # System constants, weights, thresholds
│   ├── db/
│   │   ├── connection.py             # SQLite WAL connection manager
│   │   └── queries.py                # CRUD queries for updates, ROAs, and alerts
│   ├── core/
│   │   ├── prefix_trie.py            # High-performance IP Radix Trie
│   │   ├── rpki_validator.py         # Strict RFC 6811 validation logic
│   │   ├── bogon_filter.py           # Bogon IP & private ASN detection
│   │   └── explainability.py         # Evidence dossier generation
│   ├── ml/
│   │   ├── feature_extractor.py      # BGP feature engineering
│   │   ├── isolation_forest.py       # Unsupervised path & outlier scoring
│   │   ├── hitl_classifier.py        # Supervised Random Forest with continuous feedback
│   │   └── pipeline.py               # Combined scoring orchestrator
│   ├── ingestion/
│   │   ├── real_world_fetcher.py     # Live RIPE Stat & Looking Glass collector harvester
│   │   ├── synthetic_generator.py    # Synthetic hijack & multi-homing injector
│   │   └── stream_simulator.py       # Stream replayer & live batch controller
│   └── services/
│       └── monitor_service.py        # Master pipeline orchestrator
├── components/
│   ├── soc_header.py                 # Top KPI metrics & latency display
│   ├── alert_inspector.py            # Evidence cards & 1-click HITL actions
│   ├── live_feed.py                  # Live BGP telemetry feed table
│   ├── route_inspector.py            # Live Route Inspector & AS_PATH visual graph
│   ├── threat_analytics.py           # Precision, Recall, Confusion Matrix, Latency gauge
│   └── roa_explorer.py               # RPKI ROA explorer & prefix validator sandbox
└── tests/
    ├── test_rfc6811.py               # RFC 6811 & Bogon unit tests
    ├── test_ml_pipeline.py           # Feature extraction & ML tests
    └── test_synthetic_harness.py     # End-to-end benchmark tests
```

---

## 🛠️ Getting Started

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run Test Suite
```bash
python -m unittest discover tests
```

### 3. Launch Streamlit SOC Dashboard
```bash
streamlit run app.py
```
Then navigate to `http://localhost:8501` in your browser.

---

## 📊 Evaluation Deliverables

| Deliverable | Result | Target Benchmark |
| :--- | :--- | :--- |
| **RFC 6811 Origin Validation** | 100% agreement on test vectors | 100% compliant |
| **Subprefix Hijack Detection** | 100% recall on /24 inside /20 ROAs | > 95% |
| **Processing Latency** | ~5.7 - 14 ms per update | < 50 ms |
| **Recall (Malicious Hijacks)** | 1.0000 | > 0.90 |
| **Precision** | > 0.85 - 0.95 | High precision |
| **False Positive Rate** | < 0.05 | Effectively ignores benign multi-homing |
