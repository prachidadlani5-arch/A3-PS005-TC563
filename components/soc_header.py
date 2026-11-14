import streamlit as st
from typing import Dict, Any

def render_soc_header(counts: Dict[str, Any], telemetry: Dict[str, Any]) -> None:
    """Renders the top cybersecurity SOC header and KPI metrics."""
    st.markdown(
        """
        <div style="background: linear-gradient(90deg, #0d1117 0%, #161b22 100%); 
                    padding: 18px 24px; border-radius: 10px; border-left: 5px solid #238636;
                    box-shadow: 0 4px 12px rgba(0,0,0,0.4); margin-bottom: 24px;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <h2 style="margin: 0; color: #f0f6fc; font-weight: 700; letter-spacing: 0.5px;">
                        🛡️ Explainable BGP Origin & Subprefix Anomaly Monitor
                    </h2>
                    <p style="margin: 4px 0 0 0; color: #8b949e; font-size: 14px;">
                        RFC 6811 Compliant &bull; Passive Routing Watchdog &bull; AIORI Hackathon 2026 (PS-005)
                    </p>
                </div>
                <div>
                    <span style="background-color: #238636; color: #ffffff; padding: 6px 14px; 
                                 border-radius: 20px; font-weight: 600; font-size: 12px; letter-spacing: 1px;">
                        ● PASSIVE WATCHDOG ACTIVE
                    </span>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # Calculate percentages for RFC states
    total_updates = max(1, counts.get("total_updates", 0))
    rpki_counts = counts.get("rpki_counts", {})
    valid_count = rpki_counts.get("VALID", 0)
    not_found_count = rpki_counts.get("NOT_FOUND", 0)
    invalid_count = sum(v for k, v in rpki_counts.items() if "INVALID" in k)

    valid_pct = (valid_count / total_updates) * 100
    invalid_pct = (invalid_count / total_updates) * 100

    latency_ms = telemetry.get("avg_latency_ms", 12.4)
    latency_color = "normal" if latency_ms < 50.0 else "inverse"

    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.metric(label="Total Updates", value=f"{counts.get('total_updates', 0):,}")
    with col2:
        st.metric(label="RFC 6811 Valid", value=f"{valid_count:,}", delta=f"{valid_pct:.1f}%")
    with col3:
        st.metric(label="RFC 6811 Invalids", value=f"{invalid_count:,}", delta=f"{invalid_pct:.1f}%", delta_color="inverse")
    with col4:
        st.metric(label="Pending Review", value=f"{counts.get('pending_alerts', 0):,}", delta="HITL Queue")
    with col5:
        st.metric(label="Avg Latency", value=f"{latency_ms:.1f} ms", delta="< 50ms Target", delta_color=latency_color)

    st.divider()
