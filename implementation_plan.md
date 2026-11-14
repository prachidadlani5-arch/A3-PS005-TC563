# Implementation Plan: Explainable BGP Origin and Subprefix Anomaly Monitor

**Project**: PS-005: Explainable BGP Origin and Subprefix Anomaly Monitor  
**Track**: Cybersecurity & Routing Infrastructure (AIORI Hackathon 2026)  
**Standard Compliance**: RFC 6811 (BGP Prefix-to-AS Mapping Validation), RFC 5398 / 6996 / 7300 (Bogon/Private ASNs)  
**Target Environment**: Python 3.10+, SQLite/DuckDB, Scikit-learn, Streamlit SOC Dashboard  

---

## 1. Executive System Architecture

The monitor is a strictly **passive security watchdog** that ingests replayed or live BGP feeds (RIPE RIS / RouteViews), validates updates against time-aligned RPKI Route Origin Authorizations (ROAs), applies deterministic RFC 6811 rules and bogon filters, and enriches detections with an adaptive Machine Learning layer (Isolation Forest + HITL-trained Random Forest). Every alert produces a transparent, human-readable evidence dossier.

```
                            +-----------------------------------+
                            |  BGP Feed (RIPE RIS / RouteViews)  |
                            |  + Synthetic Anomaly Injector     |
                            +-----------------+-----------------+
                                              |
                                              v
+------------------------+          +-------------------+
|  RPKI ROA Validator    | -------->|  Ingestion Engine  |
|  (RIPE NCC Cache)      |          |  & State Resolver |
+------------------------+          +---------+---------+
                                              |
                                              v
                                    +-------------------+
                                    | RFC 6811 Engine   |
                                    | Valid / NotFound  |
                                    | Invalid (ASN/Len) |
                                    +---------+---------+
                                              |
                        +---------------------+---------------------+
                        |                                           |
                        v                                           v
            +-----------------------+                   +-----------------------+
            | Deterministic Filters |                   | Adaptive ML Layer     |
            | - Unexpected Origin   |                   | - Isolation Forest    |
            | - Subprefix Hijack    |                   | - Path Length Spikes  |
            | - Bogon / Private AS  |                   | - Random Forest (HITL)|
            +-----------+-----------+                   +-----------+-----------+
                        |                                           |
                        +---------------------+---------------------+
                                              |
                                              v
                                    +-------------------+
                                    | Explainability    |
                                    | Evidence Engine   |
                                    +---------+---------+
                                              |
                                              v
                                    +-------------------+
                                    | SQLite / DuckDB   |
                                    | Storage Layer     |
                                    +---------+---------+
                                              |
                                              v
                                    +-------------------+
                                    | Streamlit SOC UI  |
                                    | - Feed Inspector  |
                                    | - Threat Matrix   |
                                    | - HITL Review     |
                                    | - Perf Benchmark  |
                                    +-------------------+
```

---

## 2. Database Schema (SQLite / DuckDB)

The storage layer uses SQLite with Write-Ahead Logging (WAL) for concurrency, low latency, and zero external dependencies.

```sql
-- 1. RPKI Route Origin Authorizations (ROA) Table
CREATE TABLE IF NOT EXISTS roas (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    prefix TEXT NOT NULL,                -- e.g. '192.0.2.0/24', '2001:db8::/32'
    max_length INTEGER NOT NULL,         -- e.g. 24
    asn INTEGER NOT NULL,                -- Authorized Origin ASN (e.g. 13335)
    tai TEXT DEFAULT 'RIPE NCC',         -- Trust Anchor (RIPE, ARIN, APNIC, etc.)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_roas_prefix ON roas(prefix);
CREATE INDEX IF NOT EXISTS idx_roas_asn ON roas(asn);

-- 2. Ingested BGP Updates Stream
CREATE TABLE IF NOT EXISTS bgp_updates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TIMESTAMP NOT NULL,
    peer_ip TEXT NOT NULL,
    peer_asn INTEGER NOT NULL,
    prefix TEXT NOT NULL,
    origin_asn INTEGER NOT NULL,
    as_path TEXT NOT NULL,               -- Space-delimited string (e.g. "3356 1299 13335")
    as_path_len INTEGER NOT NULL,
    rpki_state TEXT NOT NULL,            -- 'VALID', 'NOT_FOUND', 'INVALID_ASN', 'INVALID_LENGTH'
    is_bogon INTEGER DEFAULT 0,          -- 1 if ASN or Prefix is bogon/private
    is_synthetic INTEGER DEFAULT 0       -- 1 if injected by synthetic test harness
);
CREATE INDEX IF NOT EXISTS idx_bgp_updates_prefix ON bgp_updates(prefix);
CREATE INDEX IF NOT EXISTS idx_bgp_updates_origin ON bgp_updates(origin_asn);
CREATE INDEX IF NOT EXISTS idx_bgp_updates_timestamp ON bgp_updates(timestamp);

-- 3. Anomaly Alerts & Detections
CREATE TABLE IF NOT EXISTS anomaly_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    update_id INTEGER NOT NULL REFERENCES bgp_updates(id),
    timestamp TIMESTAMP NOT NULL,
    prefix TEXT NOT NULL,
    origin_asn INTEGER NOT NULL,
    expected_asn TEXT,                   -- JSON list of authorized ASNs from matching ROAs
    anomaly_type TEXT NOT NULL,          -- 'UNEXPECTED_ORIGIN', 'SUBPREFIX_HIJACK', 'BOGON_ASN', 'PATH_SPIKE'
    severity TEXT NOT NULL,              -- 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
    rule_verdict TEXT NOT NULL,          -- RFC 6811 State or Bogon Trigger
    ml_anomaly_score REAL NOT NULL,      -- Isolation Forest score [0.0 - 1.0]
    rf_confidence REAL NOT NULL,         -- Supervised HITL model probability [0.0 - 1.0]
    threat_score REAL NOT NULL,          -- Combined weighted risk index [0.0 - 100.0]
    explainability_summary TEXT NOT NULL,-- Plain English diagnostic sentence
    evidence_json TEXT NOT NULL,         -- JSON payload containing ROA rules, delta len, path stats
    status TEXT DEFAULT 'PENDING_REVIEW',-- 'PENDING_REVIEW', 'TRUE_POSITIVE', 'FALSE_POSITIVE', 'AUTO_RESOLVED'
    reviewed_at TIMESTAMP,
    reviewed_by TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON anomaly_alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON anomaly_alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_type ON anomaly_alerts(anomaly_type);

-- 4. Human-in-the-Loop Operator Feedback Log
CREATE TABLE IF NOT EXISTS operator_feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id INTEGER NOT NULL REFERENCES anomaly_alerts(id),
    operator_label TEXT NOT NULL,        -- 'TRUE_POSITIVE' (real hijack) or 'FALSE_POSITIVE' (multi-homing/peering change)
    notes TEXT,
    retrained_in_model_version TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 5. System Performance & Latency Telemetry
CREATE TABLE IF NOT EXISTS telemetry_metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updates_processed INTEGER NOT NULL,
    alerts_triggered INTEGER NOT NULL,
    avg_latency_ms REAL NOT NULL,
    precision REAL,
    recall REAL,
    f1_score REAL,
    false_positive_rate REAL
);
```

---

## 3. Core Software Modules & Architecture Interfaces

The codebase is organized into clean, decoupleable components with clear APIs:

```
bgp_anomaly_monitor/
├── data/
│   ├── roas_sample.json              # RPKI snapshot sample
│   ├── bgp_updates_sample.json       # RIPE RIS / RouteViews historical updates
│   └── synthetic_test_vectors.json   # Known hijacks & legitimate multi-homing tests
├── src/
│   ├── __init__.py
│   ├── config.py                     # System constants, weights, RFC thresholds
│   ├── db/
│   │   ├── __init__.py
│   │   ├── connection.py             # SQLite connection & migration manager
│   │   └── queries.py                # CRUD queries for updates, ROAs, and alerts
│   ├── core/
│   │   ├── __init__.py
│   │   ├── prefix_trie.py            # High-performance Radix/Patricia Trie for IP prefixes
│   │   ├── rpki_validator.py         # Strict RFC 6811 validation engine
│   │   ├── bogon_filter.py           # Bogon IP & private ASN detector
│   │   └── explainability.py         # Evidence generation and natural language explainer
│   ├── ml/
│   │   ├── __init__.py
│   │   ├── feature_extractor.py      # AS_PATH, churn, subprefix depth feature pipeline
│   │   ├── isolation_forest.py       # Unsupervised path & anomaly scorer
│   │   ├── hitl_classifier.py        # Supervised Random Forest with continuous feedback loop
│   │   └── pipeline.py               # Combined ML scoring engine
│   ├── ingestion/
│   │   ├── __init__.py
│   │   ├── stream_simulator.py       # Replayer for BGP MRT/JSON stream
│   │   └── synthetic_generator.py    # Synthetic hijack & multi-homing injector
│   └── services/
│       ├── __init__.py
│       ├── monitor_service.py        # Orchestrates ingestion -> validation -> ML -> alert
│       └── feedback_service.py       # Handles operator review & model retraining
├── app.py                            # Streamlit entry point
├── components/                       # Streamlit UI visual components
│   ├── __init__.py
│   ├── soc_header.py                 # Live KPI counters & latency badge
│   ├── live_feed.py                  # Real-time BGP telemetry table
│   ├── alert_inspector.py            # Evidence card & HITL review actions
│   ├── threat_analytics.py           # Severity charts, ROC curves, confusion matrix
│   └── roa_explorer.py               # Searchable RPKI validation workbench
└── tests/
    ├── test_rfc6811.py               # RFC 6811 compliance tests
    ├── test_bogon.py                 # Bogon validation tests
    ├── test_ml_pipeline.py           # ML feature & training tests
    └── test_synthetic_harness.py     # Evaluation metrics (Precision/Recall/Latency)
```

### Key Python Interfaces & Service Signatures

#### A. RFC 6811 Validator (`src/core/rpki_validator.py`)
```python
class RPKIValidationState(str, Enum):
    VALID = "VALID"
    NOT_FOUND = "NOT_FOUND"
    INVALID_ASN = "INVALID_ASN"
    INVALID_LENGTH = "INVALID_LENGTH"

@dataclass
class ValidationResult:
    state: RPKIValidationState
    matched_roas: list[dict]
    reason: str

class RPKIValidator:
    def __init__(self, roa_records: list[dict]):
        """Initializes Radix Trie with (prefix, max_length, authorized_asn)."""
    
    def validate(self, prefix: str, origin_asn: int) -> ValidationResult:
        """Evaluates prefix and origin ASN in strict compliance with RFC 6811:
        1. Find covering ROA(s) where ROA.prefix contains prefix.
        2. If no covering ROA exists -> NOT_FOUND.
        3. If covering ROA exists:
           - Check if prefix.length <= ROA.max_length AND origin_asn == ROA.asn -> VALID.
           - If prefix.length > ROA.max_length -> INVALID_LENGTH.
           - If origin_asn != ROA.asn -> INVALID_ASN.
        """
```

#### B. Bogon & Private ASN Filter (`src/core/bogon_filter.py`)
```python
class BogonFilter:
    RESERVED_ASNS = [
        (0, 0),                       # RFC 7607
        (23456, 23456),               # AS_TRANS (RFC 6793)
        (64496, 64511),               # Documentation (RFC 5398)
        (64512, 65534),               # Private 16-bit (RFC 6996)
        (65535, 65535),               # Reserved (RFC 7300)
        (65536, 65551),               # Documentation 32-bit (RFC 5398)
        (65552, 131071),              # Reserved
        (4200000000, 4294967294),     # Private 32-bit (RFC 6996)
        (4294967295, 4294967295)      # Reserved
    ]

    @staticmethod
    def is_bogon_asn(asn: int) -> tuple[bool, str]: ...
    @staticmethod
    def is_bogon_prefix(prefix: str) -> tuple[bool, str]: ...
```

#### C. Adaptive ML Layer (`src/ml/pipeline.py`)
```python
@dataclass
class AnomalyScore:
    isolation_forest_score: float  # [0.0 - 1.0] (unsupervised outlier score)
    rf_confidence: float           # [0.0 - 1.0] (probability of malicious hijack from HITL model)
    composite_threat_score: float  # [0.0 - 100.0]
    path_spike_flag: bool

class AnomalyMLPipeline:
    def extract_features(self, update: BGPUpdate, history: HistoricalContext) -> np.ndarray: ...
    def score_update(self, features: np.ndarray, rpki_verdict: str) -> AnomalyScore: ...
    def retrain_hitl(self, feedback_data: list[FeedbackRecord]) -> ModelMetrics: ...
```

#### D. Explainability Engine (`src/core/explainability.py`)
```python
@dataclass
class ExplainabilityReport:
    headline: str               # e.g., "Critical Subprefix Hijack Detected"
    natural_language: str       # Clear diagnostic summary
    evidence_breakdown: dict    # Exact ROA comparisons, prefix length delta, path anomalies
    recommended_action: str     # Strictly passive operator guidance (e.g., verify peering change)

class ExplainabilityEngine:
    def explain(self, update: BGPUpdate, val_res: ValidationResult, ml_score: AnomalyScore) -> ExplainabilityReport: ...
```

---

## 4. UI Component Tree (Streamlit SOC Dashboard)

The Streamlit dashboard is structured as a mission-critical Security Operations Center (SOC) dashboard:

```
App Root (app.py)
├── Sidebar: System Controls & Feed Selector
│   ├── Replay Controls (Play, Pause, Step, Speed: 1x/5x/10x)
│   ├── Synthetic Anomaly Generator (Inject Subprefix, Inject Bad Origin, Inject Multi-home)
│   ├── ML Sensitivity Slider (Threshold: 50 - 90)
│   └── Database Reset & Seed Buttons
│
├── Main View 1: Top SOC Header (`components/soc_header.py`)
│   ├── KPI Metric: Updates Processed (Total & Rate/sec)
│   ├── KPI Metric: RFC 6811 State Breakdown (Valid %, NotFound %, Invalid %)
│   ├── KPI Metric: Active Critical Alerts
│   ├── KPI Metric: False Positive Rate (FPR)
│   └── KPI Metric: Ingestion to Alert Latency (ms)
│
├── Tab 1: 🚨 Live Alert & HITL Review Queue (`components/alert_inspector.py`)
│   ├── Priority Filters (All, Critical, High, Medium, Pending Review)
│   ├── Alert Cards (Severity badge, Timestamp, Affected Prefix, Offending ASN)
│   ├── Explainability Drawer (Expandable):
│   │   ├── RFC 6811 Evidence Box (Expected ASN vs Observed ASN, Max Length vs Actual)
│   │   ├── AS Path Visualizer (Hop breakdown: Peer -> Transit -> Origin)
│   │   ├── ML Feature Attribution (Path length z-score, Novel origin flag)
│   │   └── Passive Advisory (e.g. "Passive Alert: Route not blackholed")
│   └── HITL Decision Actions:
│       ├── Button: "Confirm True Positive (Malicious Hijack)"
│       ├── Button: "Mark False Positive (Legitimate Multi-homing / Policy)"
│       └── Retrain Status Pill ("Retrained on 14 operator decisions")
│
├── Tab 2: 📡 Live Telemetry Stream (`components/live_feed.py`)
│   ├── Search & Filter Bar (by ASN, Prefix, RFC state)
│   ├── Real-time Ingestion Table with Color-coded RFC 6811 Badges
│   └── Real-time Processing Latency Distribution Histogram
│
├── Tab 3: 📊 Model Analytics & Synthetic Benchmark (`components/threat_analytics.py`)
│   ├── Hackathon Evaluation Deliverables:
│   │   ├── Confusion Matrix (True Positives, False Positives, False Negatives)
│   │   ├── Precision, Recall, F1-Score Cards
│   │   ├── Latency Benchmark Gauge (Target: < 50ms per update)
│   │   └── Operator Feedback Drift Graph (FP reduction over time)
│   └── Synthetic Test Suite Runner:
│       └── Test Cases: YouTube Hijack (AS36561 vs AS17557), Cloudflare Subprefix test, Multi-homing shift
│
└── Tab 4: 🛡️ RPKI ROA Repository Explorer (`components/roa_explorer.py`)
    ├── Filterable Database of Validated ROAs
    └── Prefix Lookup Simulator: Test any prefix/ASN tuple against the active Radix Trie
```

---

## 5. Step-by-Step Assembly & Execution Plan

### Phase 1: Environment & Project Foundation
- **Step 1.1**: Initialize project directory structure (`src/`, `data/`, `components/`, `tests/`).
- **Step 1.2**: Generate `requirements.txt` with locked dependencies (`streamlit`, `pandas`, `scikit-learn`, `numpy`, `plotly`).
- **Step 1.3**: Implement database initialization and schema migration scripts (`src/db/connection.py`, `src/db/queries.py`).

### Phase 2: RFC 6811 Validation & Bogon Rules Engine
- **Step 2.1**: Build `PrefixTrie` (`src/core/prefix_trie.py`) using `ipaddress` for longest-prefix matching.
- **Step 2.2**: Implement strict RFC 6811 logic in `src/core/rpki_validator.py` (`VALID`, `NOT_FOUND`, `INVALID_ASN`, `INVALID_LENGTH`).
- **Step 2.3**: Build Bogon/Private ASN and Prefix filter in `src/core/bogon_filter.py`.
- **Step 2.4**: Unit test RFC 6811 and Bogon logic against test vectors in `tests/test_rfc6811.py`.

### Phase 3: Adaptive ML Layer & Explainability
- **Step 3.1**: Implement feature extraction pipeline in `src/ml/feature_extractor.py` (AS_PATH length, prefix specificity, path churn, novel peer/origin pairing).
- **Step 3.2**: Implement `IsolationForest` unsupervised detector in `src/ml/isolation_forest.py` for anomalous routing bursts.
- **Step 3.3**: Implement `RandomForestClassifier` HITL model in `src/ml/hitl_classifier.py` with continuous retraining capability.
- **Step 3.4**: Implement `ExplainabilityEngine` in `src/core/explainability.py` generating transparent, human-readable rationale strings.

### Phase 4: Data Ingestion & Synthetic Test Harness
- **Step 4.1**: Create sample historical BGP updates and RPKI ROAs snapshots in `data/`.
- **Step 4.2**: Build synthetic anomaly injector (`src/ingestion/synthetic_generator.py`) supporting:
  - Unauthorized Origin Hijack (Invalid-ASN)
  - /24 Subprefix Hijack (Invalid-Length)
  - Bogon/Private ASN Injection
  - Legitimate Multi-homing Route Flap (Benign control test)
- **Step 4.3**: Implement stream replayer service (`src/ingestion/stream_simulator.py`) for live telemetry emulation.

### Phase 5: Streamlit SOC Dashboard Assembly
- **Step 5.1**: Build the main Streamlit application layout (`app.py`) with cybersecurity theme and tabs.
- **Step 5.2**: Implement `soc_header.py` with real-time KPI metrics and latency badges.
- **Step 5.3**: Build `alert_inspector.py` with explainable evidence cards and interactive 1-click HITL feedback buttons.
- **Step 5.4**: Build `live_feed.py` displaying the real-time BGP telemetry table.
- **Step 5.5**: Build `threat_analytics.py` computing Precision, Recall, Confusion Matrix, and Alert Latency.
- **Step 5.6**: Build `roa_explorer.py` for manual prefix-to-ROA verification.

### Phase 6: System Verification & Deliverable Validation
- **Step 6.1**: Run automated test suite (`tests/`) verifying RFC 6811, Bogon, ML, and synthetic evaluation.
- **Step 6.2**: Measure end-to-end alert latency (target: < 50ms) and false positive rate under multi-homing traffic.
- **Step 6.3**: Verify Streamlit dashboard interactivity, feedback loop retraining, and evidence string clarity.

---

## 6. Evaluation Deliverables & Verification Matrix

| Hackathon Requirement | System Implementation | Verification Metric |
| :--- | :--- | :--- |
| **RFC 6811 Origin Validation** | `src/core/rpki_validator.py` with Radix Trie | 100% agreement on RFC test vectors (`Valid`, `NotFound`, `Invalid-ASN`, `Invalid-Length`) |
| **Subprefix Hijack Detection** | Prefix length > ROA MaxLength check | Detects 100% of injected /24 within /16-/20 ROAs |
| **Adaptive ML Layer** | Isolation Forest + Random Forest | F1-Score > 0.95 on synthetic anomaly suite |
| **Explainable Evidence** | `src/core/explainability.py` human-readable strings | Clear textual proof showing ROA rules vs observed BGP update |
| **Human-in-the-Loop (HITL)** | Streamlit 1-Click feedback + online retraining | False positive rate drops with operator feedback |
| **Processing Latency** | Optimized in-memory pipeline with SQLite WAL | Sub-50ms ingestion-to-alert latency |
| **Strictly Passive** | Passive watchdog, no route blackholing | Operator alerts and advisories only |
