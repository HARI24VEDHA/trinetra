import streamlit as st
import tempfile
import socket
import pandas as pd
import base64
import ipaddress
import os
import json
import hashlib
from datetime import datetime
import uuid
import shutil

from ui.theme import apply_theme
from ui.dashboard import show_dashboard
from ui.metrics import show_metrics
from ui.permission_popup import show_permission_popup

from core.report_generator import generate_soc_report
from core.parser import parse_pcap
from core.flows import reconstruct_flows
from core.ai_detection import detect_suspicious
from core.geoip_locator import locate_ips
from core.graph_builder import build_graph
from core.packet_capture import capture_packets
from core.message_hashes import extract_message_hashes
from core.anonymity_detector import detect_anonymity


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
# SESSION STATE INIT
# -----------------------------
if "report_path" not in st.session_state:
    st.session_state["report_path"] = None

if "selected_history_id" not in st.session_state:
    st.session_state["selected_history_id"] = None


# -----------------------------
# DNS CACHE + RESOLVER
# -----------------------------
dns_cache = {}


def resolve_domain(ip):
    if ip in dns_cache:
        return dns_cache[ip]

    try:
        ipaddress.ip_address(ip)
        domain = socket.gethostbyaddr(ip)[0]
    except Exception:
        domain = "Unknown"

    dns_cache[ip] = domain
    return domain


# -----------------------------
# INVESTIGATION CACHE STORAGE
# -----------------------------
CACHE_DIR = "cache"
CACHE_FILE = os.path.join(CACHE_DIR, "investigation_history.json")
INVESTIGATION_DIR = os.path.join(CACHE_DIR, "investigations")

os.makedirs(CACHE_DIR, exist_ok=True)
os.makedirs(INVESTIGATION_DIR, exist_ok=True)

if not os.path.exists(CACHE_FILE):
    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump([], f)


def load_history():
    try:
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def save_history(data):
    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)


def generate_file_hash(file_path):
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            sha256.update(chunk)

    return sha256.hexdigest()


def check_existing_analysis(file_hash):
    history = load_history()

    for entry in history:
        if entry.get("file_hash") == file_hash:
            return entry

    return None


def make_json_safe(obj):
    if obj is None:
        return []

    if isinstance(obj, pd.DataFrame):
        df_copy = obj.copy()
        for col in df_copy.columns:
            if pd.api.types.is_datetime64_any_dtype(df_copy[col]):
                df_copy[col] = df_copy[col].astype(str)
        return df_copy.to_dict(orient="records")

    if isinstance(obj, pd.Series):
        return obj.to_list()

    if isinstance(obj, dict):
        return {str(k): make_json_safe(v) for k, v in obj.items()}

    if isinstance(obj, list):
        return [make_json_safe(x) for x in obj]

    if isinstance(obj, tuple):
        return [make_json_safe(x) for x in obj]

    if isinstance(obj, (str, int, float, bool)):
        return obj

    return str(obj)


def save_json_file(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(make_json_safe(data), f, indent=4)


def load_json_file(path, default_value):
    if not os.path.exists(path):
        return default_value

    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default_value


def normalize_locations_for_storage(locations):
    if locations is None:
        return []

    if isinstance(locations, pd.DataFrame):
        return make_json_safe(locations)

    if isinstance(locations, list):
        normalized = []
        for item in locations:
            if isinstance(item, dict):
                lat = item.get("lat", item.get("latitude", item.get("Latitude")))
                lon = item.get("lon", item.get("longitude", item.get("Longitude")))
                ip = item.get("ip", item.get("IP", "Unknown"))

                if isinstance(lat, list) and len(lat) > 0:
                    lat = lat[0]
                if isinstance(lon, list) and len(lon) > 0:
                    lon = lon[0]

                normalized.append({
                    "ip": ip,
                    "lat": lat,
                    "lon": lon
                })
            else:
                normalized.append(item)
        return normalized

    if isinstance(locations, dict):
        lat = locations.get("lat", locations.get("latitude", locations.get("Latitude")))
        lon = locations.get("lon", locations.get("longitude", locations.get("Longitude")))
        ip = locations.get("ip", locations.get("IP", "Unknown"))

        if isinstance(lat, list) and len(lat) > 0:
            lat = lat[0]
        if isinstance(lon, list) and len(lon) > 0:
            lon = lon[0]

        return [{
            "ip": ip,
            "lat": lat,
            "lon": lon
        }]

    return []


def save_investigation_artifacts(
    display_name,
    source_name,
    df,
    flows,
    suspicious,
    locations,
    vpn_results,
    message_hashes,
    file_hash=None
):
    history = load_history()

    investigation_id = str(uuid.uuid4())
    folder_path = os.path.join(INVESTIGATION_DIR, investigation_id)
    os.makedirs(folder_path, exist_ok=True)

    df_to_save = df.copy()
    if "time" in df_to_save.columns:
        df_to_save["time"] = df_to_save["time"].astype(str)

    df_to_save.to_json(
        os.path.join(folder_path, "df.json"),
        orient="records",
        indent=4
    )

    save_json_file(os.path.join(folder_path, "flows.json"), flows)
    save_json_file(os.path.join(folder_path, "suspicious.json"), suspicious)
    save_json_file(
        os.path.join(folder_path, "locations.json"),
        normalize_locations_for_storage(locations)
    )
    save_json_file(os.path.join(folder_path, "vpn_results.json"), vpn_results)
    save_json_file(os.path.join(folder_path, "message_hashes.json"), message_hashes)

    suspicious_count = len(suspicious) if suspicious is not None else 0
    vpn_detected = True if vpn_results else False

    entry = {
        "investigation_id": investigation_id,
        "file_hash": file_hash if file_hash else str(hash(source_name + datetime.now().isoformat())),
        "file_name": display_name,
        "source_name": source_name,
        "timestamp": datetime.now().isoformat(),
        "suspicious_count": suspicious_count,
        "vpn_detected": vpn_detected,
        "folder_path": folder_path
    }

    history.append(entry)
    save_history(history)


def load_investigation_artifacts(investigation_id):
    folder_path = os.path.join(INVESTIGATION_DIR, investigation_id)

    if not os.path.exists(folder_path):
        return None

    df_path = os.path.join(folder_path, "df.json")
    flows_path = os.path.join(folder_path, "flows.json")
    suspicious_path = os.path.join(folder_path, "suspicious.json")
    locations_path = os.path.join(folder_path, "locations.json")
    vpn_results_path = os.path.join(folder_path, "vpn_results.json")
    message_hashes_path = os.path.join(folder_path, "message_hashes.json")

    if not os.path.exists(df_path):
        return None

    df = pd.read_json(df_path)

    if "time" in df.columns:
        df["time"] = pd.to_datetime(df["time"], errors="coerce")

    flows_raw = load_json_file(flows_path, [])
    suspicious_raw = load_json_file(suspicious_path, [])
    locations_raw = load_json_file(locations_path, [])
    vpn_results = load_json_file(vpn_results_path, [])
    message_hashes = load_json_file(message_hashes_path, [])

    if isinstance(flows_raw, list):
        flows = pd.DataFrame(flows_raw)
    elif isinstance(flows_raw, dict):
        flows = pd.DataFrame([flows_raw])
    else:
        flows = pd.DataFrame()

    if isinstance(suspicious_raw, list):
        suspicious = pd.DataFrame(suspicious_raw)
    elif isinstance(suspicious_raw, dict):
        suspicious = pd.DataFrame([suspicious_raw])
    else:
        suspicious = pd.DataFrame()

    if isinstance(locations_raw, list):
        locations = pd.DataFrame(locations_raw)
    elif isinstance(locations_raw, dict):
        locations = pd.DataFrame([locations_raw])
    else:
        locations = pd.DataFrame()

    if not locations.empty:
        rename_map = {}

        if "latitude" in locations.columns:
            rename_map["latitude"] = "lat"
        if "longitude" in locations.columns:
            rename_map["longitude"] = "lon"
        if "Latitude" in locations.columns:
            rename_map["Latitude"] = "lat"
        if "Longitude" in locations.columns:
            rename_map["Longitude"] = "lon"

        if rename_map:
            locations = locations.rename(columns=rename_map)

        for col in ["lat", "lon"]:
            if col in locations.columns:
                locations[col] = locations[col].apply(
                    lambda x: x[0] if isinstance(x, list) and len(x) > 0 else x
                )
                locations[col] = pd.to_numeric(locations[col], errors="coerce")

        if "lat" in locations.columns and "lon" in locations.columns:
            locations = locations.dropna(subset=["lat", "lon"])
        else:
            locations = pd.DataFrame(columns=["lat", "lon"])
    else:
        locations = pd.DataFrame(columns=["lat", "lon"])

    G = build_graph(df)

    return {
        "df": df,
        "flows": flows,
        "suspicious": suspicious,
        "locations": locations,
        "vpn_results": vpn_results,
        "message_hashes": message_hashes,
        "G": G
    }


def delete_investigation(investigation_id):
    history = load_history()
    updated_history = []
    folder_to_delete = None

    for entry in history:
        if entry.get("investigation_id") == investigation_id:
            folder_to_delete = entry.get("folder_path")
        else:
            updated_history.append(entry)

    save_history(updated_history)

    if folder_to_delete and os.path.exists(folder_to_delete):
        shutil.rmtree(folder_to_delete, ignore_errors=True)


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
        if st.session_state["report_path"]:
            with open(st.session_state["report_path"], "rb") as f:
                st.download_button(
                    label="Download SOC Report",
                    data=f,
                    file_name="trinetra_soc_report.pdf",
                    mime="application/pdf"
                )

    if st.session_state["report_path"]:
        st.subheader("View Report")

        with open(st.session_state["report_path"], "rb") as f:
            base64_pdf = base64.b64encode(f.read()).decode("utf-8")

        pdf_display = f"""
        <iframe src="data:application/pdf;base64,{base64_pdf}" 
        width="100%" height="600px"></iframe>
        """

        st.markdown(pdf_display, unsafe_allow_html=True)


def show_loaded_investigation(data):
    df = data["df"]
    flows = data["flows"]
    suspicious = data["suspicious"]
    locations = data["locations"]
    vpn_results = data["vpn_results"]
    message_hashes = data["message_hashes"]
    G = data["G"]

    show_metrics(df, suspicious)
    show_dashboard(df, flows, suspicious, locations, None, G, message_hashes)

    st.subheader("VPN Detection")

    if vpn_results:
        vpn_df = pd.DataFrame(vpn_results)
        st.dataframe(vpn_df)
    else:
        st.success("No VPN gateway detected.")

    show_report_section(df, suspicious)


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


# -----------------------------
# INVESTIGATION HISTORY
# -----------------------------
st.sidebar.divider()
st.sidebar.subheader("Investigation History")

history = load_history()

if history:
    for entry in reversed(history):
        with st.sidebar.expander(entry["file_name"]):
            st.write(f"**Time:** {entry['timestamp']}")
            st.write(f"**Suspicious Count:** {entry['suspicious_count']}")
            st.write(f"**VPN Detected:** {'Yes' if entry['vpn_detected'] else 'No'}")

            col1, col2 = st.columns(2)

            with col1:
                if st.button("Open", key=f"open_{entry['investigation_id']}"):
                    st.session_state["selected_history_id"] = entry["investigation_id"]
                    st.rerun()

            with col2:
                if st.button("Delete", key=f"delete_{entry['investigation_id']}"):
                    delete_investigation(entry["investigation_id"])
                    if st.session_state["selected_history_id"] == entry["investigation_id"]:
                        st.session_state["selected_history_id"] = None
                    st.rerun()
else:
    st.sidebar.info("No investigations yet.")


# -----------------------------
# LOAD PREVIOUS INVESTIGATION
# -----------------------------
if st.session_state["selected_history_id"] is not None:
    loaded_data = load_investigation_artifacts(st.session_state["selected_history_id"])

    if loaded_data is not None:
        st.success("Previous investigation loaded successfully.")

        if st.button("Close History View"):
            st.session_state["selected_history_id"] = None
            st.rerun()

        show_loaded_investigation(loaded_data)
        st.stop()
    else:
        st.warning("Previous investigation data not found.")
        st.session_state["selected_history_id"] = None


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

            file_hash = generate_file_hash(temp.name)
            cached = check_existing_analysis(file_hash)

            if cached:
                st.info("Previous investigation found in cache.")

            df = parse_pcap(temp.name)
            df = df.replace(["", "None"], None)
            df = df.dropna(subset=["src_ip", "dst_ip"])

            if df is None or df.empty:
                st.warning("No packets extracted from PCAP.")
                st.stop()

            if "time" not in df.columns:
                st.error("Timestamp column missing in parsed PCAP.")
                st.stop()

            df["time"] = pd.to_datetime(df["time"], errors="coerce")
            df = df.head(50000)

            message_hashes = extract_message_hashes(df)

            if "dst_ip" in df.columns:
                unique_ips = df["dst_ip"].dropna().unique()
                dns_map = {ip: resolve_domain(ip) for ip in unique_ips}
                df["dst_domain"] = df["dst_ip"].map(dns_map)
            else:
                df["dst_domain"] = "Unknown"

            flows = reconstruct_flows(df)
            suspicious = detect_suspicious(df)
            locations = locate_ips(df)
            vpn_results = detect_anonymity(df)
            G = build_graph(df)

            save_investigation_artifacts(
                display_name=uploaded_file.name,
                source_name=temp.name,
                df=df,
                flows=flows,
                suspicious=suspicious,
                locations=locations,
                vpn_results=vpn_results,
                message_hashes=message_hashes,
                file_hash=file_hash
            )

        show_metrics(df, suspicious)
        show_dashboard(df, flows, suspicious, locations, None, G, message_hashes)

        st.subheader("VPN Detection")

        if vpn_results:
            vpn_df = pd.DataFrame(vpn_results)
            st.dataframe(vpn_df)
        else:
            st.success("No VPN gateway detected.")

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
            df = df.head(50000)

            message_hashes = extract_message_hashes(df)

            if "dst_ip" in df.columns:
                unique_ips = df["dst_ip"].dropna().unique()
                dns_map = {ip: resolve_domain(ip) for ip in unique_ips}
                df["dst_domain"] = df["dst_ip"].map(dns_map)
            else:
                df["dst_domain"] = "Unknown"

            flows = reconstruct_flows(df)
            suspicious = detect_suspicious(df)
            locations = locate_ips(df)
            anonymity_results = detect_anonymity(df)
            G = build_graph(df)

            save_investigation_artifacts(
                display_name=f"Live Capture - {interface}",
                source_name=interface,
                df=df,
                flows=flows,
                suspicious=suspicious,
                locations=locations,
                anonymity_results=anonymity_results,
                message_hashes=message_hashes,
                file_hash=None
            )

        show_metrics(df, suspicious)
        show_dashboard(df, flows, suspicious, locations, None, G, message_hashes)

        st.subheader("VPN Detection")

        if anonymity_results:
            vpn_df = pd.DataFrame(anonymity_results)
            st.dataframe(vpn_df)
        else:
            st.success("No VPN gateway detected.")

        show_report_section(df, suspicious)
