import json
import streamlit as st
from typing import Dict, Any, List
from src.db.queries import get_alerts, update_alert_review, get_operator_feedback
from src.services.monitor_service import BGPMonitorService

def render_alert_inspector() -> None:
    """Renders the Alert Inspector and Human-in-the-Loop (HITL) Review Queue."""
    st.subheader("🚨 Anomaly Alerts & Operator Review Queue (HITL)")
    st.caption("RFC 6811 transparent evidence dossier with human-in-the-loop validation and online model retraining.")

    # Filter controls
    col_filter, col_retrain = st.columns([3, 1])
    with col_filter:
        status_filter = st.selectbox(
            "Filter Alerts by Review Status:",
            ["PENDING_REVIEW", "ALL", "CRITICAL", "TRUE_POSITIVE", "FALSE_POSITIVE"],
            index=0
        )
    with col_retrain:
        st.write("")
        st.write("")
        if st.button("🔄 Retrain ML with Feedback", type="primary"):
            service = BGPMonitorService.get_instance()
            retrain_result = service.retrain_from_operator_feedback()
            if retrain_result.get("status") == "retrained_successfully":
                st.success(f"Model retrained on {retrain_result['samples_trained']} decisions!")
            else:
                st.info("No operator feedback recorded yet. Review alerts below to train the model.")

    alerts = get_alerts(status_filter=status_filter if status_filter not in ("CRITICAL", "ALL") else None, limit=40)
    if status_filter == "CRITICAL":
        alerts = [a for a in alerts if a["severity"] == "CRITICAL"]

    if not alerts:
        st.info("No alerts found matching the selected filter criteria.")
        return

    # Severity color mapping
    severity_colors = {
        "CRITICAL": "#da3633",
        "HIGH": "#d29922",
        "MEDIUM": "#e3b341",
        "LOW": "#58a6ff",
        "INFO": "#8b949e"
    }

    for alert in alerts:
        sev_color = severity_colors.get(alert["severity"], "#8b949e")
        evidence = json.loads(alert["evidence_json"]) if isinstance(alert["evidence_json"], str) else alert["evidence_json"]
        expected_asns = json.loads(alert["expected_asn"]) if isinstance(alert["expected_asn"], str) and alert["expected_asn"].startswith("[") else alert["expected_asn"]

        with st.container():
            st.markdown(
                f"""
                <div style="border: 1px solid #30363d; border-left: 6px solid {sev_color}; 
                            border-radius: 8px; padding: 14px 18px; margin-bottom: 14px; background-color: #0d1117;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                        <div>
                            <span style="background-color: {sev_color}; color: white; padding: 3px 8px; 
                                         border-radius: 4px; font-weight: bold; font-size: 11px;">
                                {alert["severity"]}
                            </span>
                            <span style="font-weight: 600; color: #f0f6fc; margin-left: 8px; font-size: 16px;">
                                {alert["anomaly_type"].replace('_', ' ')}
                            </span>
                            <span style="color: #8b949e; font-size: 13px; margin-left: 10px;">
                                Target Prefix: <code style="color: #58a6ff;">{alert["prefix"]}</code> &bull; Origin: <code style="color: #ec775c;">AS{alert["origin_asn"]}</code>
                            </span>
                        </div>
                        <div>
                            <span style="color: #8b949e; font-size: 12px;">Threat Score:</span>
                            <span style="font-weight: 700; color: {'#f85149' if alert['threat_score'] >= 70 else '#e3b341'}; font-size: 16px;">
                                {alert["threat_score"]:.1f}/100
                            </span>
                        </div>
                    </div>
                    <div style="background-color: #161b22; padding: 10px 14px; border-radius: 6px; 
                                border: 1px solid #21262d; margin-bottom: 8px; font-size: 14px; color: #c9d1d9;">
                        <strong>Diagnostic Rationale:</strong> {alert["explainability_summary"]}
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

            with st.expander(f"🔍 Inspect Full Evidence Dossier & HITL Actions (Alert #{alert['id']})"):
                col_ev1, col_ev2 = st.columns(2)
                with col_ev1:
                    st.markdown("**🛡️ RFC 6811 Validation Proof:**")
                    st.write(f"- **Announced Prefix:** `{alert['prefix']}`")
                    st.write(f"- **Announced Origin ASN:** `AS{alert['origin_asn']}`")
                    st.write(f"- **RFC 6811 Verdict:** `{alert['rule_verdict']}`")
                    st.write(f"- **ROA Authorized ASNs:** `{expected_asns}`")
                    if evidence.get("authorized_max_lengths"):
                        st.write(f"- **ROA Authorized Max Length:** `/{max(evidence['authorized_max_lengths'])}` (Announced length: `/{evidence.get('as_path_length', 'N/A')}`)")

                with col_ev2:
                    st.markdown("**🤖 ML Attribution & Path Metrics:**")
                    st.write(f"- **Supervised P(Hijack) (Random Forest):** `{alert['rf_confidence'] * 100:.1f}%`")
                    st.write(f"- **Outlier Score (Isolation Forest):** `{alert['ml_anomaly_score'] * 100:.1f}%`")
                    st.write(f"- **AS_PATH Hops:** `{evidence.get('as_path', [])}`")
                    st.write(f"- **Review Status:** `{alert['status']}`")

                st.markdown(
                    """
                    <div style="background-color: #1f242c; padding: 8px 12px; border-radius: 4px; font-size: 12px; color: #8b949e; margin: 8px 0;">
                        ⚠️ <strong>Passive Security Watchdog Policy:</strong> No automated route blackholing or route hijacking suppression was initiated. Alerts are presented for operator verification.
                    </div>
                    """,
                    unsafe_allow_html=True
                )

                # Human-In-The-Loop Decision Section
                st.markdown("##### 👤 Human-in-the-Loop (HITL) Decision")
                c_btn1, c_btn2, c_notes = st.columns([1, 1, 2])
                with c_notes:
                    notes = st.text_input(f"Operator Notes (#{alert['id']}):", key=f"notes_{alert['id']}")
                with c_btn1:
                    if st.button("🚨 Confirm True Positive", key=f"tp_{alert['id']}", use_container_width=True):
                        update_alert_review(alert["id"], "TRUE_POSITIVE", notes)
                        st.success("Marked as True Positive (Malicious Hijack). Added to retraining corpus.")
                        st.rerun()
                with c_btn2:
                    if st.button("✅ Mark False Positive", key=f"fp_{alert['id']}", use_container_width=True):
                        update_alert_review(alert["id"], "FALSE_POSITIVE", notes)
                        st.info("Marked as False Positive (Benign Multi-homing / Policy). Added to retraining corpus.")
                        st.rerun()
