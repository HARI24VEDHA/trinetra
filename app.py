import streamlit as st
import tempfile
import socket
import pandas as pd
import base64

from ui.theme import apply_theme
from ui.dashboard import show_dashboard
from ui.metrics import show_metrics
from ui.permission_popup import show_permission_popup
from core.report_generator import generate_soc_report

from core.parser import parse_pcap
from core.flows import reconstruct_flows
from core.ai_detection import detect_suspicious
from core.geoip_locator import locate_ips
from core.timeline import build_timeline
from core.graph_builder import build_graph
from core.packet_capture import capture_packets


# -----------------------------
# DNS CACHE + RESOLVER
# -----------------------------
dns_cache = {}

def resolve_domain(ip):

    if ip in dns_cache:
        return dns_cache[ip]

    try:
        domain = socket.gethostbyaddr(ip)[0]
    except:
        domain = "Unknown"

    dns_cache[ip] = domain
    return domain


# -----------------------------
# SOC REPORT SECTION
# -----------------------------
def show_report_section(df, suspicious):

    st.divider()
    st.subheader("SOC Analyst Investigation Report")

    col1, col2 = st.columns(2)

    with col1:
        if st.button("Generate SOC Report"):

            report_file = generate_soc_report(df, suspicious)

            st.session_state["report_path"] = report_file

            st.success("SOC Report Generated Successfully")

    with col2:

        if "report_path" in st.session_state:

            with open(st.session_state["report_path"], "rb") as f:

                st.download_button(
                    label="Download SOC Report",
                    data=f,
                    file_name="trinetra_soc_report.pdf",
                    mime="application/pdf"
                )

    # -----------------------------
    # VIEW REPORT
    # -----------------------------
    if "report_path" in st.session_state:

        st.subheader("View Report")

        with open(st.session_state["report_path"], "rb") as f:

            base64_pdf = base64.b64encode(f.read()).decode("utf-8")

        pdf_display = f"""
        <iframe src="data:application/pdf;base64,{base64_pdf}" 
        width="100%" height="600px"></iframe>
        """

        st.markdown(pdf_display, unsafe_allow_html=True)


# -----------------------------
# STREAMLIT PAGE CONFIG
# -----------------------------
st.set_page_config(
    page_title="TRINETRA Cyber Intelligence",
    layout="wide",
    page_icon="🛡️"
)

apply_theme()

st.markdown("""
# 🛡️ TRINETRA  
### Cyber Forensics Intelligence Platform
""")

st.sidebar.title("Investigation Console")


# -----------------------------
# USER AUTHORIZATION
# -----------------------------
permission = show_permission_popup()

if not permission:
    st.stop()


# -----------------------------
# MODE SELECTION
# -----------------------------
mode = st.sidebar.radio(
    "Select Investigation Mode",
    ["Upload PCAP", "Live Capture"]
)


# =====================================================
# PCAP FILE ANALYSIS MODE
# =====================================================
if mode == "Upload PCAP":

    uploaded_file = st.sidebar.file_uploader(
        "Upload PCAP File",
        type=["pcap"]
    )

    if uploaded_file:

        st.success("PCAP Uploaded Successfully")

        temp = tempfile.NamedTemporaryFile(delete=False)
        temp.write(uploaded_file.read())
        temp.close()

        with st.spinner("Analyzing PCAP Traffic..."):

            df = parse_pcap(temp.name)

            if df is None or df.empty:
                st.warning("No packets were extracted from the PCAP file.")
                st.stop()

            if "time" not in df.columns:
                st.error("Timestamp column missing in parsed PCAP.")
                st.stop()

            df["time"] = pd.to_datetime(df["time"], errors="coerce")

            # DNS resolution
            if "dst_ip" in df.columns:
                unique_ips = df["dst_ip"].dropna().unique()
                dns_map = {ip: resolve_domain(ip) for ip in unique_ips}
                df["dst_domain"] = df["dst_ip"].map(dns_map)
            else:
                df["dst_domain"] = "Unknown"

            flows = reconstruct_flows(df)
            suspicious = detect_suspicious(df)
            locations = locate_ips(df)
            timeline = build_timeline(df)
            G = build_graph(df)

        show_metrics(df, suspicious)

        show_dashboard(df, flows, suspicious, locations, timeline, G)

        show_report_section(df, suspicious)


# =====================================================
# LIVE PACKET CAPTURE MODE
# =====================================================
elif mode == "Live Capture":

    interface = st.sidebar.text_input(
        "Network Interface",
        "Wi-Fi"
    )

    packet_count = st.sidebar.slider(
        "Number of Packets to Capture",
        50,
        1000,
        200
    )

    if st.sidebar.button("Start Capture"):

        with st.spinner("Capturing Live Packets..."):

            df = capture_packets(interface, packet_count)

            if df is None or df.empty:
                st.warning("No packets captured.")
                st.stop()

            if "time" not in df.columns:
                st.error("Timestamp column missing in captured packets.")
                st.stop()

            df["time"] = pd.to_datetime(df["time"], errors="coerce")

            # DNS resolution
            if "dst_ip" in df.columns:
                unique_ips = df["dst_ip"].dropna().unique()
                dns_map = {ip: resolve_domain(ip) for ip in unique_ips}
                df["dst_domain"] = df["dst_ip"].map(dns_map)
            else:
                df["dst_domain"] = "Unknown"

            flows = reconstruct_flows(df)
            suspicious = detect_suspicious(df)
            locations = locate_ips(df)
            timeline = build_timeline(df)
            G = build_graph(df)

        show_metrics(df, suspicious)

        show_dashboard(df, flows, suspicious, locations, timeline, G)

        show_report_section(df, suspicious)