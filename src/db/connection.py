import sqlite3
from pathlib import Path
from src.config import DB_PATH

def get_connection(db_path: Path = DB_PATH) -> sqlite3.Connection:
    """Returns a SQLite connection configured with WAL mode and row factory."""
    conn = sqlite3.connect(str(db_path), timeout=30.0)
    conn.row_factory = sqlite3.Row
    # Enable Write-Ahead Logging for high concurrency & speed
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def init_db(db_path: Path = DB_PATH) -> None:
    """Initializes database schema and indexes."""
    conn = get_connection(db_path)
    with conn:
        conn.executescript("""
        -- 1. RPKI Route Origin Authorizations (ROAs) Table
        CREATE TABLE IF NOT EXISTS roas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            prefix TEXT NOT NULL,
            max_length INTEGER NOT NULL,
            asn INTEGER NOT NULL,
            tai TEXT DEFAULT 'RIPE NCC',
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
            as_path TEXT NOT NULL,
            as_path_len INTEGER NOT NULL,
            rpki_state TEXT NOT NULL,
            is_bogon INTEGER DEFAULT 0,
            is_synthetic INTEGER DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_bgp_updates_prefix ON bgp_updates(prefix);
        CREATE INDEX IF NOT EXISTS idx_bgp_updates_origin ON bgp_updates(origin_asn);
        CREATE INDEX IF NOT EXISTS idx_bgp_updates_timestamp ON bgp_updates(timestamp);

        -- 3. Anomaly Alerts & Detections
        CREATE TABLE IF NOT EXISTS anomaly_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            update_id INTEGER NOT NULL REFERENCES bgp_updates(id) ON DELETE CASCADE,
            timestamp TIMESTAMP NOT NULL,
            prefix TEXT NOT NULL,
            origin_asn INTEGER NOT NULL,
            expected_asn TEXT,
            anomaly_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            rule_verdict TEXT NOT NULL,
            ml_anomaly_score REAL NOT NULL,
            rf_confidence REAL NOT NULL,
            threat_score REAL NOT NULL,
            explainability_summary TEXT NOT NULL,
            evidence_json TEXT NOT NULL,
            status TEXT DEFAULT 'PENDING_REVIEW',
            reviewed_at TIMESTAMP,
            reviewed_by TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_alerts_status ON anomaly_alerts(status);
        CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON anomaly_alerts(timestamp);
        CREATE INDEX IF NOT EXISTS idx_alerts_type ON anomaly_alerts(anomaly_type);

        -- 4. Human-in-the-Loop Operator Feedback Log
        CREATE TABLE IF NOT EXISTS operator_feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id INTEGER NOT NULL REFERENCES anomaly_alerts(id) ON DELETE CASCADE,
            operator_label TEXT NOT NULL,
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        -- 5. System Performance & Telemetry
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
        """)
    conn.close()

def reset_db(db_path: Path = DB_PATH) -> None:
    """Clears all tables in the database."""
    conn = get_connection(db_path)
    with conn:
        conn.executescript("""
        DELETE FROM operator_feedback;
        DELETE FROM anomaly_alerts;
        DELETE FROM bgp_updates;
        DELETE FROM telemetry_metrics;
        DELETE FROM roas;
        """)
    conn.close()
