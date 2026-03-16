def reconstruct_flows(df):

    df["flow"] = (
        df["src_ip"] +
        "-" +
        df["dst_ip"] +
        "-" +
        df["protocol"].astype(str)
    )

    flows = df.groupby("flow").size()

    return flows
