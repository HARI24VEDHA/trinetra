import streamlit as st
import pandas as pd
import networkx as nx
import plotly.express as px
import plotly.graph_objects as go


# -------------------------
# Packet Classification
# -------------------------
def classify_packet(size):

    if size < 200:
        return "Control / DNS"

    elif size < 800:
        return "Web Traffic"

    elif size < 1400:
        return "File Transfer"

    else:
        return "Large Data"


# -------------------------
# Dashboard
# -------------------------
def show_dashboard(df, flows, suspicious, locations, timeline, G, message_hashes):

    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
        "Traffic Analysis",
        "Threat Intelligence",
        "Global Map",
        "Timeline",
        "Communication Graph",
        "Communication Flows"
    ])

    # -------------------------
    # Traffic Analysis
    # -------------------------
    with tab1:

        st.subheader("Traffic Metadata")

        df["traffic_type"] = df["length"].apply(classify_packet)

        display_df = df.rename(columns={
            "src_ip": "Source IP",
            "src_port": "Source Port",
            "dst_ip": "Destination IP",
            "dst_port": "Destination Port",
            "dst_domain": "Destination Domain",
            "protocol": "Protocol",
            "length": "Packet Size (Bytes)",
            "traffic_type": "Traffic Category",
            "time": "Timestamp"
        })

        columns_to_show = [
            "Source IP",
            "Source Port",
            "Destination IP",
            "Destination Port",
            "Protocol",
            "Packet Size (Bytes)",
            "Timestamp",
            "Destination Domain",
            "Traffic Category"
        ]

        st.dataframe(
            display_df[columns_to_show].head(1000),
            use_container_width=True
        )

    # -------------------------
    # Threat Intelligence
    # -------------------------
    with tab2:

        st.subheader("Suspicious Endpoint Detection")

        if suspicious is not None and not suspicious.empty:
            st.dataframe(suspicious, use_container_width=True)
        else:
            st.info("No suspicious endpoints detected.")

        st.markdown("""
        **AI Model:** Isolation Forest  
        **Purpose:** Detect abnormal communication frequency
        """)

    # -------------------------
    # Global Map
    # -------------------------
    with tab3:

        st.subheader("Global Communication Map")

        if locations is None or len(locations) == 0:
            st.warning("No location data available.")
        else:

            geo_df = pd.DataFrame(locations)

            if "latitude" in geo_df.columns and "longitude" in geo_df.columns:

                geo_df = geo_df.dropna(subset=["latitude", "longitude"])

                if not geo_df.empty:
                    st.map(geo_df)
                else:
                    st.warning("No valid geolocation coordinates found.")

            else:
                st.warning("Latitude/Longitude columns missing.")

    # -------------------------
    # Timeline
    # -------------------------
    with tab4:

        st.subheader("Traffic Timeline")

        if "time" not in df.columns:
            st.warning("Timestamp column missing.")

        else:

            timeline_df = df.copy()

            timeline_df["time"] = pd.to_datetime(
                timeline_df["time"],
                errors="coerce"
            )

            timeline_df = timeline_df.dropna(subset=["time"])

            if timeline_df.empty:
                st.warning("No valid timestamps available for timeline.")

            else:

                timeline_df = (
                    timeline_df
                    .set_index("time")
                    .resample("1S")
                    .size()
                    .reset_index(name="packets")
                )

                fig = px.line(
                    timeline_df,
                    x="time",
                    y="packets",
                    title="Network Traffic Timeline",
                    template="plotly_dark"
                )

                st.plotly_chart(fig, use_container_width=True)

    # -------------------------
    # Communication Graph
    # -------------------------
    with tab5:

        st.subheader("Communication Network Graph")

        if G is None or len(G.nodes) == 0:
            st.warning("No graph data available.")
        else:

            pos = nx.spring_layout(G, k=0.5)

            edge_x = []
            edge_y = []

            for edge in G.edges():
                x0, y0 = pos[edge[0]]
                x1, y1 = pos[edge[1]]
                edge_x += [x0, x1, None]
                edge_y += [y0, y1, None]

            edge_trace = go.Scatter(
                x=edge_x,
                y=edge_y,
                line=dict(width=1, color="#0f2942"),
                hoverinfo='none',
                mode='lines'
            )

            node_x = []
            node_y = []
            node_text = []

            for node in G.nodes():
                x, y = pos[node]
                node_x.append(x)
                node_y.append(y)
                node_text.append(node)

            node_trace = go.Scatter(
                x=node_x,
                y=node_y,
                mode='markers+text',
                text=node_text,
                textposition="top center",
                hoverinfo='text',
                marker=dict(size=12, color="#4da6ff")
            )

            fig = go.Figure(
                data=[edge_trace, node_trace],
                layout=go.Layout(
                    title="IP Communication Network",
                    showlegend=False,
                    hovermode='closest'
                )
            )

            st.plotly_chart(fig, use_container_width=True)

    # -------------------------
    # Communication Flows
    # -------------------------
    with tab6:

        st.subheader("Communication Flows Analysis")

        if flows is None or flows.empty:
            st.warning("No communication flow data available.")

        else:

            flow_df = flows.copy()

            flow_df["Flow"] = (
                flow_df["src_ip"] + ":" +
                flow_df["src_port"].astype(str) +
                " → " +
                flow_df["dst_ip"] + ":" +
                flow_df["dst_port"].astype(str)
            )

            st.dataframe(
                flow_df[
                    ["Flow", "protocol", "packet_count", "bytes"]
                ].sort_values("packet_count", ascending=False),
                use_container_width=True
            )

            st.subheader("Top Communication Flows")

            top_flows = flow_df.sort_values(
                "packet_count",
                ascending=False
            ).head(10)

            fig = px.bar(
                top_flows,
                x="Flow",
                y="packet_count",
                title="Top Communication Flows",
                template="plotly_dark"
            )

            st.plotly_chart(fig, use_container_width=True)

    # -----------------------------
    # Encrypted Message Hashes
    # -----------------------------
    st.divider()

    st.subheader("Encrypted Message Hashes")

    if message_hashes and len(message_hashes) > 0:

        hash_df = pd.DataFrame(message_hashes)

        st.dataframe(hash_df, use_container_width=True)

    else:

        st.info("No encrypted message payload hashes detected.")
