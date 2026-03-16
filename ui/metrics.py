import streamlit as st

def show_metrics(df, suspicious):

    st.markdown("## Threat Overview")

    st.markdown('<div class="metric-row">', unsafe_allow_html=True)

    col1,col2,col3,col4 = st.columns(4)

    col1.markdown(f"""
    <div class="metric-card">
        <div class="metric-title">Total Packets</div>
        <div class="metric-value">{len(df)}</div>
    </div>
    """, unsafe_allow_html=True)

    col2.markdown(f"""
    <div class="metric-card">
        <div class="metric-title">Unique Endpoints</div>
        <div class="metric-value">{df["dst_ip"].nunique()}</div>
    </div>
    """, unsafe_allow_html=True)

    col3.markdown(f"""
    <div class="metric-card">
        <div class="metric-title">Suspicious Endpoints</div>
        <div class="metric-value">{len(suspicious)}</div>
    </div>
    """, unsafe_allow_html=True)

    col4.markdown(f"""
    <div class="metric-card">
        <div class="metric-title">Unique Sources</div>
        <div class="metric-value">{df["src_ip"].nunique()}</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown('</div>', unsafe_allow_html=True)
