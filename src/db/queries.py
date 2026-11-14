import json
import sqlite3
from typing import Any, Dict, List, Optional
from src.db.connection import get_connection

def insert_roas(roas: List[Dict[str, Any]], conn: Optional[sqlite3.Connection] = None) -> int:
    """Batch inserts ROAs into the roas table."""
    should_close = False
    if conn is None:
        conn = get_connection()
        should_close = True
    
    with conn:
        cursor = conn.executemany(
            """
            INSERT INTO roas (prefix, max_length, asn, tai)
            VALUES (:prefix, :max_length, :asn, :tai)
            """,
            roas
        )
        count = cursor.rowcount
    if should_close:
        conn.close()
    return count

def get_all_roas(conn: Optional[sqlite3.Connection] = None) -> List[Dict[str, Any]]:
    """Retrieves all ROA entries."""
    should_close = False
    if conn is None:
        conn = get_connection()
        should_close = True
    
    cursor = conn.execute("SELECT id, prefix, max_length, asn, tai, created_at FROM roas")
    rows = [dict(r) for r in cursor.fetchall()]
    if should_close:
        conn.close()
    return rows

def insert_bgp_update(update: Dict[str, Any], conn: Optional[sqlite3.Connection] = None) -> int:
    """Inserts a single BGP update and returns its generated id."""
    should_close = False
    if conn is None:
        conn = get_connection()
        should_close = True
        
    with conn:
        cursor = conn.execute(
            """
            INSERT INTO bgp_updates (
                timestamp, peer_ip, peer_asn, prefix, origin_asn, 
                as_path, as_path_len, rpki_state, is_bogon, is_synthetic
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                update["timestamp"], update["peer_ip"], update["peer_asn"],
                update["prefix"], update["origin_asn"], update["as_path"],
                update["as_path_len"], update["rpki_state"],
                update.get("is_bogon", 0), update.get("is_synthetic", 0)
            )
        )
        update_id = cursor.lastrowid
    if should_close:
        conn.close()
    return update_id

def insert_anomaly_alert(alert: Dict[str, Any], conn: Optional[sqlite3.Connection] = None) -> int:
    """Inserts an anomaly alert and returns its generated id."""
    should_close = False
    if conn is None:
        conn = get_connection()
        should_close = True
        
    evidence_str = json.dumps(alert.get("evidence_json", {})) if isinstance(alert.get("evidence_json"), dict) else str(alert.get("evidence_json", "{}"))
    expected_asn_str = json.dumps(alert.get("expected_asn", [])) if isinstance(alert.get("expected_asn"), list) else str(alert.get("expected_asn", ""))

    with conn:
        cursor = conn.execute(
            """
            INSERT INTO anomaly_alerts (
                update_id, timestamp, prefix, origin_asn, expected_asn,
                anomaly_type, severity, rule_verdict, ml_anomaly_score,
                rf_confidence, threat_score, explainability_summary,
                evidence_json, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert["update_id"], alert["timestamp"], alert["prefix"],
                alert["origin_asn"], expected_asn_str, alert["anomaly_type"],
                alert["severity"], alert["rule_verdict"], alert["ml_anomaly_score"],
                alert["rf_confidence"], alert["threat_score"],
                alert["explainability_summary"], evidence_str,
                alert.get("status", "PENDING_REVIEW")
            )
        )
        alert_id = cursor.lastrowid
    if should_close:
        conn.close()
    return alert_id

def get_recent_updates(limit: int = 50, conn: Optional[sqlite3.Connection] = None) -> List[Dict[str, Any]]:
    """Retrieves recent BGP updates."""
    should_close = False
    if conn is None:
        conn = get_connection()
        should_close = True
        
    cursor = conn.execute(
        "SELECT * FROM bgp_updates ORDER BY id DESC LIMIT ?",
        (limit,)
    )
    rows = [dict(r) for r in cursor.fetchall()]
    if should_close:
        conn.close()
    return rows

def get_alerts(status_filter: Optional[str] = None, limit: int = 100, conn: Optional[sqlite3.Connection] = None) -> List[Dict[str, Any]]:
    """Retrieves alerts with optional status filtering."""
    should_close = False
    if conn is None:
        conn = get_connection()
        should_close = True
        
    if status_filter and status_filter != "ALL":
        cursor = conn.execute(
            "SELECT * FROM anomaly_alerts WHERE status = ? ORDER BY id DESC LIMIT ?",
            (status_filter, limit)
        )
    else:
        cursor = conn.execute(
            "SELECT * FROM anomaly_alerts ORDER BY id DESC LIMIT ?",
            (limit,)
        )
    rows = [dict(r) for r in cursor.fetchall()]
    if should_close:
        conn.close()
    return rows

def update_alert_review(alert_id: int, operator_label: str, notes: Optional[str] = None, reviewer: str = "SOC_Analyst", conn: Optional[sqlite3.Connection] = None) -> None:
    """Records operator review for an alert and logs feedback."""
    should_close = False
    if conn is None:
        conn = get_connection()
        should_close = True
        
    with conn:
        conn.execute(
            """
            UPDATE anomaly_alerts 
            SET status = ?, reviewed_at = CURRENT_TIMESTAMP, reviewed_by = ?
            WHERE id = ?
            """,
            (operator_label, reviewer, alert_id)
        )
        conn.execute(
            """
            INSERT INTO operator_feedback (alert_id, operator_label, notes)
            VALUES (?, ?, ?)
            """,
            (alert_id, operator_label, notes or "")
        )
    if should_close:
        conn.close()

def get_operator_feedback(conn: Optional[sqlite3.Connection] = None) -> List[Dict[str, Any]]:
    """Retrieves all operator feedback entries paired with alert features for ML retraining."""
    should_close = False
    if conn is None:
        conn = get_connection()
        should_close = True
        
    cursor = conn.execute(
        """
        SELECT f.id, f.alert_id, f.operator_label, f.notes, f.created_at,
               a.prefix, a.origin_asn, a.anomaly_type, a.rule_verdict,
               a.ml_anomaly_score, a.rf_confidence, a.threat_score, a.evidence_json,
               u.as_path, u.as_path_len, u.rpki_state
        FROM operator_feedback f
        JOIN anomaly_alerts a ON f.alert_id = a.id
        JOIN bgp_updates u ON a.update_id = u.id
        ORDER BY f.id ASC
        """
    )
    rows = [dict(r) for r in cursor.fetchall()]
    if should_close:
        conn.close()
    return rows

def record_telemetry(metrics: Dict[str, Any], conn: Optional[sqlite3.Connection] = None) -> None:
    """Records telemetry performance metrics."""
    should_close = False
    if conn is None:
        conn = get_connection()
        should_close = True
        
    with conn:
        conn.execute(
            """
            INSERT INTO telemetry_metrics (
                updates_processed, alerts_triggered, avg_latency_ms,
                precision, recall, f1_score, false_positive_rate
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                metrics["updates_processed"], metrics["alerts_triggered"],
                metrics["avg_latency_ms"], metrics.get("precision"),
                metrics.get("recall"), metrics.get("f1_score"),
                metrics.get("false_positive_rate")
            )
        )
    if should_close:
        conn.close()

def get_system_counts(conn: Optional[sqlite3.Connection] = None) -> Dict[str, int]:
    """Retrieves aggregate counts for the SOC dashboard header."""
    should_close = False
    if conn is None:
        conn = get_connection()
        should_close = True
        
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM bgp_updates")
    total_updates = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM anomaly_alerts")
    total_alerts = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM anomaly_alerts WHERE severity = 'CRITICAL'")
    critical_alerts = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM anomaly_alerts WHERE status = 'PENDING_REVIEW'")
    pending_alerts = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM roas")
    total_roas = c.fetchone()[0]

    c.execute("SELECT rpki_state, COUNT(*) FROM bgp_updates GROUP BY rpki_state")
    rpki_counts = dict(c.fetchall())

    if should_close:
        conn.close()

    return {
        "total_updates": total_updates,
        "total_alerts": total_alerts,
        "critical_alerts": critical_alerts,
        "pending_alerts": pending_alerts,
        "total_roas": total_roas,
        "rpki_counts": rpki_counts
    }
