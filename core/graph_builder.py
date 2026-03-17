import networkx as nx

def build_graph(df):

    G = nx.Graph()

    # -------------------------
    # Basic validation
    # -------------------------
    if df is None or df.empty:
        print("[Graph] Empty dataframe received")
        return G

    if "src_ip" not in df.columns or "dst_ip" not in df.columns:
        print("[Graph] Required columns missing")
        return G

    try:

        # -------------------------
        # Clean data
        # -------------------------
        clean_df = df.copy()

        clean_df["src_ip"] = clean_df["src_ip"].astype(str)
        clean_df["dst_ip"] = clean_df["dst_ip"].astype(str)

        # Remove invalid values
        clean_df = clean_df[
            (clean_df["src_ip"] != "None") &
            (clean_df["dst_ip"] != "None") &
            (clean_df["src_ip"] != "") &
            (clean_df["dst_ip"] != "")
        ]

        # Drop NaN values
        clean_df = clean_df.dropna(subset=["src_ip", "dst_ip"])

        # -------------------------
        # Check after cleaning
        # -------------------------
        if clean_df.empty:
            print("[Graph] No valid IP data after cleaning")
            return G

        # -------------------------
        # Build graph safely
        # -------------------------
        for _, row in clean_df.iterrows():

            try:
                src = row["src_ip"]
                dst = row["dst_ip"]

                if src and dst:
                    G.add_edge(str(src), str(dst))

            except Exception:
                # Skip problematic rows silently
                continue

    except Exception as e:
        print(f"[Graph Error] {e}")

    return G