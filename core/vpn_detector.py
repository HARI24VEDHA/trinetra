import pandas as pd


def detect_vpn(df):

    if df is None or df.empty:
        return []

    if "dst_ip" not in df.columns or "length" not in df.columns:
        return []

    temp = df.copy()

    # Group traffic by destination
    stats = temp.groupby("dst_ip").agg(
        packet_count=("length", "count"),
        avg_packet_size=("length", "mean"),
        total_bytes=("length", "sum")
    ).reset_index()

    vpn_candidates = []

    for _, row in stats.iterrows():

        # Simple VPN heuristic
        if row["packet_count"] > 100 and row["avg_packet_size"] > 800:

            vpn_candidates.append({
                "dst_ip": row["dst_ip"],
                "packet_count": int(row["packet_count"]),
                "avg_packet_size": round(row["avg_packet_size"], 2),
                "total_bytes": int(row["total_bytes"]),
                "suspected_service": "Possible VPN Tunnel"
            })

    return vpn_candidates