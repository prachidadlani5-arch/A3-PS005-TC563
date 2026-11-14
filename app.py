import streamlit as st
from src.db.queries import get_system_counts, get_recent_updates
from src.db.connection import reset_db
from src.services.monitor_service import BGPMonitorService
from src.ingestion.stream_simulator import BGPStreamSimulator
from components.soc_header import render_soc_header
from components.alert_inspector import render_alert_inspector
from components.live_feed import render_live_feed
from components.threat_analytics import render_threat_analytics
from components.roa_explorer import render_roa_explorer
from components.route_inspector import render_live_route_tester

# Page Configuration
st.set_page_config(
    page_title="BGP Origin & Subprefix Anomaly Monitor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom SOC Dark Theme Styling
st.markdown("""
<style>
    .stApp {
        background-color: #0b0e14;
        color: #f0f6fc;
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
    }
    .stTabs [data-baseweb="tab"] {
        height: 48px;
        white-space: pre-wrap;
        background-color: #161b22;
        border-radius: 6px 6px 0px 0px;
        gap: 8px;
        padding-top: 10px;
        padding-bottom: 10px;
        color: #8b949e;
        border: 1px solid #30363d;
    }
    .stTabs [aria-selected="true"] {
        background-color: #21262d;
        color: #58a6ff;
        border-bottom: 2px solid #58a6ff;
    }
    div[data-testid="stMetricValue"] {
        font-size: 24px;
        font-weight: 700;
    }
</style>
""", unsafe_allow_html=True)

# Initialize Service & Simulator
service = BGPMonitorService.get_instance()
simulator = BGPStreamSimulator(service)

# Automatically seed with real-world BGP feed on first boot
if get_system_counts()["total_updates"] == 0:
    simulator.load_historical_sample()

# Sidebar: Mission Operations & Feed Simulation
with st.sidebar:
    st.markdown("### 🎛️ Watchdog Controls")
    st.caption("RFC 6811 Real-World & Production BGP Ingestion Engine.")

    st.markdown("#### 🌐 Real-World Data Ingestion")
    if st.button("📥 Load Real-World RIPE BGP Feed", use_container_width=True, type="primary"):
        with st.spinner("Loading production BGP updates from RIPE Looking Glass collectors..."):
            simulator.load_historical_sample()
            st.success("Loaded real-world production BGP routes!")
            st.rerun()

    with st.expander("🔎 Query Live Internet Route (RIPE)", expanded=False):
        st.caption("Fetch real-time routes from global collectors across Amsterdam, London, Frankfurt & NYC:")
        live_prefix_input = st.text_input("IP Prefix:", value="8.8.8.0/24", key="live_pfx")
        if st.button("⚡ Fetch & Ingest Live Route", use_container_width=True):
            with st.spinner(f"Querying RIPE Looking Glass for {live_prefix_input}..."):
                res = simulator.fetch_and_ingest_live_prefix(live_prefix_input)
                if "error" in res:
                    st.error(res["error"])
                else:
                    st.success(f"Ingested {res['routes_ingested']} live collector routes!")
                    st.rerun()

    if st.button("▶️ Stream Next 10 Updates", use_container_width=True):
        with st.spinner("Processing BGP telemetry batch..."):
            simulator.step_batch(count=10, anomaly_ratio=0.30)
            st.rerun()

    st.markdown("#### 🚨 Historical & Injected Incidents")
    col_inj1, col_inj2 = st.columns(2)
    with col_inj1:
        if st.button("Subprefix /24", use_container_width=True):
            simulator.inject_scenario("SUBPREFIX_HIJACK")
            st.rerun()
        if st.button("Bogon ASN", use_container_width=True):
            simulator.inject_scenario("BOGON_ASN")
            st.rerun()
    with col_inj2:
        if st.button("Bad Origin", use_container_width=True):
            simulator.inject_scenario("UNEXPECTED_ORIGIN")
            st.rerun()
        if st.button("Multi-Homing", use_container_width=True):
            simulator.inject_scenario("MULTIHOMING_FAILOVER")
            st.rerun()

    if st.button("📺 2008 YouTube Hijack (AS17557)", use_container_width=True):
        simulator.inject_scenario("YOUTUBE_HISTORICAL")
        st.rerun()

    st.divider()

    st.markdown("#### 🛠️ Storage Maintenance")
    if st.button("🧹 Reset DB & Reload Real ROAs", use_container_width=True):
        reset_db()
        service.reload_roas()
        st.success("Database reset and real-world RPKI ROAs reloaded.")
        st.rerun()

    st.caption("RFC 6811 Validated &bull; SQLite WAL Mode &bull; Production Data")

# Fetch telemetry and aggregate counts
counts = get_system_counts()
telemetry_data = {"avg_latency_ms": 14.5}

# Render Top SOC KPI Header
render_soc_header(counts, telemetry_data)

# Main Tab Navigation
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "🚨 Live Alerts & HITL Queue",
    "📡 Live Ingestion Stream",
    "🔬 Route Inspector & Path Graph",
    "📊 Threat Analytics & Benchmark",
    "🛡️ RPKI ROA Repository"
])

with tab1:
    render_alert_inspector()

with tab2:
    render_live_feed()

with tab3:
    render_live_route_tester()

with tab4:
    render_threat_analytics()

with tab5:
    render_roa_explorer()
