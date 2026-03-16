from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import pandas as pd
import numpy as np
import ipaddress

def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except:
        return False

def detect_suspicious(df, threat_intel_map=None):
    """
    Detect suspicious destination IPs using behavioral metadata.
    
    Parameters:
        df : pandas.DataFrame
            Must contain: dst_ip, length, time
        threat_intel_map : dict, optional
            Example:
            {
                "185.220.101.1": "TOR exit node",
                "91.121.45.21": "Known malicious infrastructure"
            }
    
    Returns:
        suspicious : pandas.DataFrame
            Suspicious endpoints with explanation
    """

    if threat_intel_map is None:
        threat_intel_map = {}

    temp = df.copy()

    # Ensure time is numeric/datetime-safe
    if not np.issubdtype(temp["time"].dtype, np.number):
        temp["time"] = pd.to_datetime(temp["time"]).astype("int64") / 1e9

    # Build endpoint-level stats
    stats = temp.groupby("dst_ip").agg(
        connections=("dst_ip", "count"),
        avg_packet_size=("length", "mean"),
        packet_size_std=("length", "std"),
        total_bytes=("length", "sum"),
        start_time=("time", "min"),
        end_time=("time", "max")
    ).reset_index()

    stats["packet_size_std"] = stats["packet_size_std"].fillna(0)
    stats["session_duration"] = stats["end_time"] - stats["start_time"]
    stats["byte_rate"] = stats["total_bytes"] / (stats["session_duration"] + 1)

    # Remove clearly local/private IPs from suspicious logic
    stats["is_private"] = stats["dst_ip"].apply(is_private_ip)

    # Features for AI
    feature_cols = [
        "connections",
        "avg_packet_size",
        "packet_size_std",
        "total_bytes",
        "session_duration",
        "byte_rate"
    ]

    X = stats[feature_cols].fillna(0)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(
        contamination=0.08,
        n_estimators=200,
        random_state=42
    )

    stats["anomaly"] = model.fit_predict(X_scaled)
    stats["anomaly_score"] = model.decision_function(X_scaled)

    # Keep only anomalous public IPs
    suspicious = stats[(stats["anomaly"] == -1) & (~stats["is_private"])].copy()

    # Dynamic thresholds
    conn_mean = stats["connections"].mean()
    conn_std = stats["connections"].std() if stats["connections"].std() > 0 else 1

    dur_mean = stats["session_duration"].mean()
    dur_std = stats["session_duration"].std() if stats["session_duration"].std() > 0 else 1

    bytes_mean = stats["total_bytes"].mean()
    bytes_std = stats["total_bytes"].std() if stats["total_bytes"].std() > 0 else 1

    rate_mean = stats["byte_rate"].mean()
    rate_std = stats["byte_rate"].std() if stats["byte_rate"].std() > 0 else 1

    explanations = []
    threat_labels = []
    risk_levels = []

    for _, row in suspicious.iterrows():
        reasons = []

        if row["connections"] > conn_mean + 2 * conn_std:
            reasons.append("Unusually high communication frequency")

        if row["session_duration"] > dur_mean + 2 * dur_std:
            reasons.append("Long persistent communication session")

        if row["total_bytes"] > bytes_mean + 2 * bytes_std:
            reasons.append("Large volume of data transferred")

        if row["byte_rate"] > rate_mean + 2 * rate_std:
            reasons.append("High outbound traffic rate")

        if row["avg_packet_size"] > stats["avg_packet_size"].mean() * 1.8:
            reasons.append("Abnormally large average packet size")

        threat_context = threat_intel_map.get(row["dst_ip"], "No known threat intel match")
        threat_labels.append(threat_context)

        if threat_context != "No known threat intel match":
            reasons.append(f"Threat intelligence match: {threat_context}")

        if not reasons:
            reasons.append("Behavioral anomaly detected by Isolation Forest")

        explanation = ", ".join(reasons)
        explanations.append(explanation)

        # Dynamic risk scoring
        score = 0
        score += 2 if "Unusually high communication frequency" in explanation else 0
        score += 2 if "Long persistent communication session" in explanation else 0
        score += 2 if "Large volume of data transferred" in explanation else 0
        score += 2 if "High outbound traffic rate" in explanation else 0
        score += 1 if "Abnormally large average packet size" in explanation else 0
        score += 3 if threat_context != "No known threat intel match" else 0

        if score >= 7:
            risk_levels.append("High")
        elif score >= 4:
            risk_levels.append("Medium")
        else:
            risk_levels.append("Low")

    suspicious["reason"] = explanations
    suspicious["threat_intel"] = threat_labels
    suspicious["risk_level"] = risk_levels

    columns = [
        "dst_ip",
        "connections",
        "total_bytes",
        "session_duration",
        "byte_rate",
        "reason"
    ]

    return suspicious[columns].rename(columns={
        "dst_ip": "Destination IP",
        "connections": "Connections",
        "total_bytes": "Total Bytes",
        "session_duration": "Session Duration",
        "byte_rate": "Byte Rate",
        "reason": "Reason"
    })
