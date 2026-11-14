import streamlit as st
import pandas as pd
from src.db.queries import get_all_roas
from src.services.monitor_service import BGPMonitorService

def render_roa_explorer() -> None:
    """Renders the RPKI ROA Repository Explorer and interactive prefix validation workbench."""
    st.subheader("🛡️ RPKI Route Origin Authorization (ROA) Repository")
    st.caption("Active RPKI ROA cache synchronized with RIPE NCC / ARIN validators for RFC 6811 verification.")

    service = BGPMonitorService.get_instance()
    roas = get_all_roas()

    col_table, col_tester = st.columns([3, 2])

    with col_table:
        st.markdown("##### 📋 Registered ROAs in Memory")
        if roas:
            df_roas = pd.DataFrame(roas)[["id", "prefix", "max_length", "asn", "tai"]].copy()
            df_roas.rename(columns={
                "id": "ID",
                "prefix": "Prefix",
                "max_length": "Max Length",
                "asn": "Authorized ASN",
                "tai": "Trust Anchor (TAI)"
            }, inplace=True)
            st.dataframe(df_roas, use_container_width=True, hide_index=True)
        else:
            st.info("No ROAs loaded in database. Click reload in sidebar.")

    with col_tester:
        st.markdown("##### 🔬 Interactive RFC 6811 Sandbox")
        st.caption("Test how any prefix / ASN announcement evaluates against the active Radix Trie.")

        test_prefix = st.text_input("Announced Prefix:", value="93.184.216.0/24")
        test_asn = st.number_input("Announced Origin ASN:", value=15133, step=1)

        if st.button("🔎 Test Validation", use_container_width=True):
            val_res = service.validator.validate(test_prefix, int(test_asn))
            state_str = val_res.state.value

            if state_str == "VALID":
                st.success(f"**VALID**: {val_res.reason}")
            elif "INVALID" in state_str:
                st.error(f"**{state_str}**: {val_res.reason}")
            else:
                st.warning(f"**NOT_FOUND**: {val_res.reason}")

            if val_res.matched_roas:
                st.markdown("**Covering ROA(s) Matched:**")
                for r in val_res.matched_roas:
                    st.code(f"ROA: {r['prefix']} | MaxLength: /{r['max_length']} | Authorized AS: {r['asn']} ({r['tai']})")
