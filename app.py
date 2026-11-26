import streamlit as st
import json
import pandas as pd

st.set_page_config(page_title="DFIR Tri-Layer Investigation", layout="wide")
st.title("Phishing-to-Compromise Forensic Timeline")
st.markdown(
    "**Evidence Tri-Layer Cross-Correlation:** Network (PCAP/Zeek) + "
    "Memory (Volatility) + Host (Sysmon)  \n"
    "*This dashboard visualizes a safe, non-destructive classroom simulation. "
    "No real malware, encryption, or remote code execution was involved.*"
)

try:
    with open("timeline.json", "r") as f:
        events = json.load(f)
    df = pd.DataFrame(events)

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Events", len(df))
    col2.metric("Network Sessions", int((df["layer"] == "Network").sum()) if "layer" in df else 0)
    col3.metric("Host Actions", int((df["layer"] == "Host").sum()) if "layer" in df else 0)
    col4.metric("Identified PIDs", df["pid"].dropna().nunique() if "pid" in df else 0)

    st.subheader("Chronological Attack Sequence")
    layer_label = {"Network": "Network", "Host": "Host", "RAM": "Memory"}

    for _, row in df.sort_values(by="timestamp", na_position="last").iterrows():
        label = layer_label.get(row.get("layer"), "Other")
        header = f"{row.get('timestamp', 'N/A')} — [{label}] {row.get('event_type', '')}"
        with st.expander(header):
            st.write(f"**Details:** {row.get('details', '')}")
            if pd.notna(row.get("mitre_id")):
                st.info(f"**MITRE ATT&CK Mapping:** `{row['mitre_id']}`")
            if pd.notna(row.get("attributed_pid")):
                st.success(
                    f"**Correlated PID:** `{row['attributed_pid']}` "
                    f"({row.get('process_name', 'Unknown')})"
                )

    st.subheader("Raw Correlated Dataset")
    st.dataframe(df, use_container_width=True)

except FileNotFoundError:
    st.error("File `timeline.json` not found. Run `python3 correlate_engine.py` first.")
