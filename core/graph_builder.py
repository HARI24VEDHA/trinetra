import networkx as nx
import pandas as pd


def build_graph(df):
    G = nx.Graph()

    if df is None or df.empty:
        return G

    required_columns = ["src_ip", "dst_ip"]

    for col in required_columns:
        if col not in df.columns:
            return G

    for _, row in df.iterrows():
        src_ip = row["src_ip"]
        dst_ip = row["dst_ip"]

        if pd.isna(src_ip) or pd.isna(dst_ip):
            continue

        if src_ip is None or dst_ip is None:
            continue

        src_ip = str(src_ip).strip()
        dst_ip = str(dst_ip).strip()

        if src_ip == "" or dst_ip == "":
            continue

        G.add_edge(src_ip, dst_ip)

    return G
