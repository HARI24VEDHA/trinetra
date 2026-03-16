def endpoint_stats(df):

    top_dest = df["dst_ip"].value_counts().head(10)

    top_src = df["src_ip"].value_counts().head(10)

    return top_src, top_dest
