import streamlit as st


@st.dialog("TRINETRA Authorization Required", width="large")
def permission_dialog():

    st.markdown("""
TRINETRA is a forensic investigation platform designed to analyze encrypted communications using observable network metadata.

### Permissions Required
• Access uploaded PCAP files for network traffic inspection  
• Extract network-level metadata (IP addresses, protocols, timestamps, packet sizes)  
• Perform communication flow reconstruction and pattern analysis  
• Detect communication frequency and timing correlations  
• Generate investigative dashboards and communication graphs  

### Security and Privacy Notice
TRINETRA performs lawful and non-intrusive analysis based solely on observable network metadata.

The platform **does not decrypt encrypted communications**, does not access message content, and does not implement unauthorized surveillance techniques.

Users must ensure they possess **legal authorization** to analyze the uploaded network traffic.
""")

    st.divider()

    consent = st.checkbox(
        "I confirm that I have legal authorization to analyze this network traffic."
    )

    if consent:
        if st.button("Accept and Continue", use_container_width=True):
            st.session_state.permission_granted = True
            st.rerun()


def show_permission_popup():

    if "permission_granted" not in st.session_state:
        st.session_state.permission_granted = False

    if not st.session_state.permission_granted:
        permission_dialog()
        return False

    return True
