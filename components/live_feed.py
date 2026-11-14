import streamlit as st
import pandas as pd
from src.db.queries import get_recent_updates

def render_live_feed() -> None:
    """Renders the Live BGP Telemetry Stream table with RFC 6811 status tags."""
    st.subheader("📡 Live BGP Ingestion Stream")
    st.caption("Real-time telemetry stream from RIPE RIS / RouteViews route collectors.")

    updates = get_recent_updates(limit=100)

    if not updates:
        st.info("No BGP updates received yet. Start the stream or inject a batch from the sidebar.")
        return

    # Filter widgets
    c1, c2, c3 = st.columns(3)
    with c1:
        search_prefix = st.text_input("Filter by Prefix (e.g. 1.1.1.0):")
    with c2:
        search_asn = st.text_input("Filter by Origin ASN:")
    with c3:
        filter_state = st.selectbox("Filter by RFC 6811 State:", ["ALL", "VALID", "NOT_FOUND", "INVALID_ASN", "INVALID_LENGTH"])

    filtered = updates
    if search_prefix:
        filtered = [u for u in filtered if search_prefix in u["prefix"]]
    if search_asn:
        filtered = [u for u in filtered if search_asn in str(u["origin_asn"])]
    if filter_state != "ALL":
        filtered = [u for u in filtered if u["rpki_state"] == filter_state]

    df = pd.DataFrame(filtered)
    if not df.empty:
        display_df = df[[
            "id", "timestamp", "prefix", "origin_asn", "rpki_state", 
            "as_path_len", "as_path", "peer_ip", "is_bogon"
        ]].copy()
        
        display_df.rename(columns={
            "id": "ID",
            "timestamp": "Timestamp",
            "prefix": "Prefix",
            "origin_asn": "Origin ASN",
            "rpki_state": "RFC 6811 State",
            "as_path_len": "Path Hops",
            "as_path": "AS_PATH",
            "peer_ip": "Collector Peer",
            "is_bogon": "Bogon Flag"
        }, inplace=True)

        st.dataframe(
            display_df,
            use_container_width=True,
            hide_index=True,
            column_config={
                "RFC 6811 State": st.column_config.TextColumn(
                    "RFC 6811 State",
                    help="Validation status per RFC 6811 standard"
                ),
                "Bogon Flag": st.column_config.CheckboxColumn(
                    "Bogon?",
                    help="Private or reserved ASN/IP detected"
                )
            }
        )
    else:
        st.warning("No updates match the current search filters.")
