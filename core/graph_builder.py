import networkx as nx

def build_graph(df):

    G = nx.Graph()

    for i,row in df.iterrows():

        G.add_edge(row["src_ip"],row["dst_ip"])

    return G
