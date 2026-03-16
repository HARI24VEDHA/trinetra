import pandas as pd


def reconstruct_flows(df):

    flows = {}

    for _, row in df.iterrows():

        key = (
            row["src_ip"],
            row["dst_ip"],
            row["src_port"],
            row["dst_port"],
            row["protocol"]
        )

        if key not in flows:
            flows[key] = {
                "src_ip": row["src_ip"],
                "dst_ip": row["dst_ip"],
                "src_port": row["src_port"],
                "dst_port": row["dst_port"],
                "protocol": row["protocol"],
                "packet_count": 0,
                "bytes": 0
            }

        flows[key]["packet_count"] += 1
        flows[key]["bytes"] += row["length"]

    return pd.DataFrame(flows.values())
