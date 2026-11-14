import streamlit as st
import json
import plotly.graph_objects as go
from src.services.monitor_service import BGPMonitorService
from src.core.bogon_filter import BogonFilter
from src.ml.pipeline import AnomalyEvaluation

PRESET_SCENARIOS = {
    "🌐 Clean Google DNS Announcement (Valid)": {
        "prefix": "8.8.8.0/24",
        "origin_asn": 15169,
        "as_path": "3356 15169",
        "peer_ip": "195.66.225.1",
        "desc": "Legitimate route announcement for Google Public DNS authorized by ARIN ROA."
    },
    "🌐 Clean Cloudflare Anycast (Valid)": {
        "prefix": "1.1.1.0/24",
        "origin_asn": 13335,
        "as_path": "1299 13335",
        "peer_ip": "80.249.208.1",
        "desc": "Standard legitimate Anycast announcement authorized by APNIC ROA."
    },
    "🚨 2008 YouTube Subprefix Hijack (Real-World Attack)": {
        "prefix": "208.65.153.0/24",
        "origin_asn": 17557,
        "as_path": "5459 3356 3491 17557",
        "peer_ip": "195.66.225.1",
        "desc": "Pakistan Telecom (AS17557) announced /24 to hijack YouTube (AS36561's /22 ROA)."
    },
    "🚨 2018 Amazon Route 53 DNS Cryptocurrency Hijack": {
        "prefix": "205.251.193.0/24",
        "origin_asn": 10297,
        "as_path": "24115 174 10297",
        "peer_ip": "198.32.176.1",
        "desc": "Rogue origin AS10297 hijacked Amazon's DNS prefix to steal cryptocurrency."
    },
    "🛑 Bogon / Private ASN Leak Violation": {
        "prefix": "1.1.1.0/24",
        "origin_asn": 13335,
        "as_path": "5459 3356 64512 13335",
        "peer_ip": "195.66.225.1",
        "desc": "Private 16-bit ASN 64512 leaked into public transit path (RFC 6996 violation)."
    },
    "⚠️ Anomalous Route Leak / Path Prepending Spike": {
        "prefix": "199.19.112.0/24",
        "origin_asn": 394380,
        "as_path": "5459 3356 1299 2914 6453 174 3257 7018 394380 394380 394380",
        "peer_ip": "195.66.225.1",
        "desc": "Extreme path length (11 hops with prepending loops) indicating transit detour or route leak."
    }
}

def render_as_path_visualizer(hops: list, origin_asn: int, is_bogon: bool, is_hijack: bool):
    """Draws a visual node graph showing the hop-by-hop AS_PATH with color-coded risk."""
    if not hops:
        return

    nodes = []
    colors = []
    hover_texts = []

    for i, asn in enumerate(hops):
        is_origin = (i == len(hops) - 1)
        is_peer = (i == 0)
        
        bogon_flag, reason = BogonFilter.is_bogon_asn(asn)

        if bogon_flag:
            color = "#da3633"  # Red
            role = f"BOGON ASN: {reason}"
        elif is_origin and is_hijack:
            color = "#f85149"  # Bright Red
            role = "Rogue Origin ASN 🚨"
        elif is_origin:
            color = "#238636"  # Green
            role = "Authorized Origin ASN"
        elif is_peer:
            color = "#1f6feb"  # Blue
            role = "Collector Peer / Ingestion Node"
        else:
            color = "#8b949e"  # Gray
            role = "Transit Provider Hop"

        nodes.append(f"AS{asn}")
        colors.append(color)
        hover_texts.append(f"Hop {i+1}: AS{asn}<br>Role: {role}")

    # Plotly Scatter Graph for Path
    x_coords = list(range(len(hops)))
    y_coords = [0] * len(hops)

    fig = go.Figure()

    # Draw connection lines
    fig.add_trace(go.Scatter(
        x=x_coords, y=y_coords,
        mode="lines",
        line=dict(color="#30363d", width=3, dash="dot"),
        hoverinfo="none"
    ))

    # Draw nodes
    fig.add_trace(go.Scatter(
        x=x_coords, y=y_coords,
        mode="markers+text",
        marker=dict(size=36, color=colors, line=dict(color="#ffffff", width=1.5)),
        text=nodes,
        textposition="top center",
        textfont=dict(color="#f0f6fc", size=11, family="monospace"),
        hoverinfo="text",
        hovertext=hover_texts
    ))

    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        height=130,
        margin=dict(l=20, r=20, t=30, b=10),
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False, range=[-0.5, 0.5]),
        showlegend=False
    )

    st.plotly_chart(fig, use_container_width=True)


def render_live_route_tester() -> None:
    """Renders the interactive Route Tester and AS_PATH visualizer."""
    st.markdown("### 🔬 Live BGP Route Inspector & Visualizer")
    st.caption("Paste any raw BGP announcement or choose a real-world scenario to diagnose the entire pipeline in real time.")

    service = BGPMonitorService.get_instance()

    # Preset selection
    preset_name = st.selectbox(
        "💡 Quick Preset Scenarios (Real-World & Synthetic):",
        ["Custom Announcement (Paste Your Own)"] + list(PRESET_SCENARIOS.keys())
    )

    if preset_name in PRESET_SCENARIOS:
        preset = PRESET_SCENARIOS[preset_name]
        default_prefix = preset["prefix"]
        default_asn = preset["origin_asn"]
        default_path = preset["as_path"]
        default_peer = preset["peer_ip"]
        st.info(f"**Scenario Context:** {preset['desc']}")
    else:
        default_prefix = "8.8.8.0/24"
        default_asn = 15169
        default_path = "3356 1299 15169"
        default_peer = "195.66.225.1"

    c1, c2, c3, c4 = st.columns([2, 1, 3, 1])
    with c1:
        input_prefix = st.text_input("IP Prefix (CIDR):", value=default_prefix)
    with c2:
        input_asn = st.number_input("Origin ASN:", value=int(default_asn), step=1)
    with c3:
        input_path = st.text_input("AS_PATH (Space-separated hops):", value=default_path)
    with c4:
        input_peer = st.text_input("Peer Collector IP:", value=default_peer)

    col_btn1, col_btn2 = st.columns([1, 2])
    with col_btn1:
        diagnose_clicked = st.button("⚡ Diagnose Announcement Live", type="primary", use_container_width=True)

    if diagnose_clicked:
        hops = [int(h) for h in input_path.split() if h.isdigit()]
        update_payload = {
            "timestamp": "2026-11-14T12:00:00Z",
            "peer_ip": input_peer,
            "peer_asn": hops[0] if hops else int(input_asn),
            "prefix": input_prefix.strip(),
            "origin_asn": int(input_asn),
            "as_path": input_path.strip(),
            "as_path_len": len(hops) if hops else 1,
            "is_synthetic": 0
        }

        # Run diagnosis through service
        with st.spinner("Executing RFC 6811 trie match, Bogon filter, and ML pipeline..."):
            res = service.process_update(update_payload)

        st.markdown("---")
        st.markdown("#### 📋 Diagnostic Verdict & Pipeline Breakdown")

        # Visual Path Graph
        is_attack = res["severity"] in ("CRITICAL", "HIGH")
        bogon_flag = bool(BogonFilter.check_as_path_bogons(input_path))
        render_as_path_visualizer(hops, int(input_asn), bogon_flag, is_attack)

        # Result KPI cards
        k1, k2, k3, k4 = st.columns(4)
        with k1:
            st.metric("RFC 6811 State", res["rpki_state"], help="Cryptographic RPKI ROA state")
        with k2:
            st.metric("Threat Score", f"{res['threat_score']:.1f}/100", help="Weighted threat level")
        with k3:
            st.metric("Assigned Severity", res["severity"], help="Severity tier")
        with k4:
            st.metric("Latency", f"{res['latency_ms']:.2f} ms", help="Engine evaluation delay")

        # Explainability Dossier
        if res.get("dossier"):
            dossier = res["dossier"]
            callout_color = "#da3633" if is_attack else "#238636"
            st.markdown(
                f"""
                <div style="border-left: 5px solid {callout_color}; background-color: #161b22; 
                            padding: 14px 18px; border-radius: 6px; margin: 12px 0;">
                    <h5 style="color: #f0f6fc; margin: 0 0 6px 0;">{dossier.headline}</h5>
                    <p style="color: #c9d1d9; font-size: 14px; margin: 0 0 8px 0;">{dossier.summary}</p>
                    <div style="font-size: 12px; color: #8b949e;">
                        🛡️ <strong>Advisory:</strong> {dossier.passive_advisory}
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

            # Details
            with st.expander("🔍 Detailed Evidence & Attribution Breakdown"):
                st.json(dossier.evidence_breakdown)
        else:
            st.success("✅ Clean Route: Announcement matches valid ROA and internet path baseline expectations.")
