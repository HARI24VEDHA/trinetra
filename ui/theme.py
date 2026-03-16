import streamlit as st

def apply_theme():

    st.markdown("""
    <style>
                
    /* Import hacker-style fonts */
    @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;600&family=Rajdhani:wght@400;500;600&family=JetBrains+Mono&display=swap');

    /* Entire application font */
    html, body, [class*="css"] {
        font-family: 'Rajdhani', sans-serif;
        letter-spacing: 0.5px;
    }

    /* Main title */
    h1 {
        font-family: 'Orbitron', sans-serif;
        font-weight: 600;
        letter-spacing: 3px;
    }

    /* Section titles */
    h2, h3 {
        font-family: 'Orbitron', sans-serif;
        letter-spacing: 1.5px;
    }

    /* Data tables + technical info */
    .stDataFrame, code {
        font-family: 'JetBrains Mono', monospace;
        font-size: 14px;
    }

    /* Sidebar font */
    section[data-testid="stSidebar"] {
        font-family: 'Rajdhani', sans-serif;
    }

                    
    /* Section titles */
    h2 {
        font-size:28px;
        font-weight:600;
        margin-top:25px;
        margin-bottom:10px;
    }

    /* Subsection titles */
    h3 {
        font-size:22px;
        font-weight:500;
        margin-top:20px;
    }

    /* Space below metrics */
    .metric-row {
        margin-bottom:35px;
    }

    /* Table headings */
    thead tr th {
        font-size:15px !important;
        font-weight:600 !important;
        color:#8fa6c1 !important;
    }

    /* Table text */
    tbody tr td {
        font-size:14px !important;
    }

    .stApp {
        background-color: #05070f;
        color: #e6edf3;
    }

    h1 {
        color: #00aaff;
        font-size: 42px;
        font-weight: 700;
    }

    h2,h3 {
        color:#4da6ff;
    }

    section[data-testid="stSidebar"] {
        background-color:#02040a;
        border-right:1px solid #1f3b57;
    }

    .metric-card {
        background: linear-gradient(145deg,#0b1f33,#071422);
        border:1px solid #1f3b57;
        padding:25px;
        border-radius:12px;
        text-align:center;
        box-shadow:0 0 15px rgba(0,170,255,0.2);
    }

    .metric-title {
        font-size:14px;
        color:#8fa6c1;
    }

    .metric-value {
        font-size:28px;
        color:#00aaff;
        font-weight:bold;
    }

    .block-container {
        padding-top:3rem;
        padding-left:2rem;
        padding-right:2rem;
    }
                
                

    </style>
    """, unsafe_allow_html=True)
