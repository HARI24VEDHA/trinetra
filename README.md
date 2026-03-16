# TRINETRA  
**Deanonymisation of Encrypted Communications using Network Metadata Analysis**

TRINETRA is a cybersecurity intelligence and forensic analysis platform designed to assist investigators in analyzing encrypted network communications without accessing or decrypting message content. The system focuses on extracting and analyzing network-level metadata from packet captures to identify suspicious communication patterns, anonymization technologies, and potential remote communication endpoints.

The project is designed as a lawful and non-intrusive investigative tool that leverages traffic flow analysis, anomaly detection, and visualization techniques to provide actionable insights for cyber forensics investigations.

---

## Overview

Modern cybercriminals increasingly rely on privacy-focused communication platforms such as encrypted messaging applications, VPNs, and anonymization networks to conceal their activities. Traditional digital forensics techniques often struggle to identify communication participants when encryption prevents access to message content.

TRINETRA addresses this challenge by analyzing observable network metadata such as IP addresses, timestamps, ports, protocols, and traffic patterns. Instead of attempting to break encryption, the system focuses on behavioral analysis to detect suspicious communication relationships.

The platform provides investigators with a visual and analytical dashboard that helps identify abnormal communication patterns, suspicious endpoints, and anonymization infrastructure.

---

## Key Features

### Network Packet Analysis
TRINETRA processes PCAP files or captures live network traffic to extract packet-level metadata for forensic investigation.

### Metadata Extraction
The system extracts and analyzes essential network attributes including:
- Source and destination IP addresses
- Ports and protocols
- Packet size and flow information
- Communication timestamps

### Traffic Flow Reconstruction
Network traffic is grouped into communication flows to identify persistent connections between endpoints.

### AI-based Suspicious Endpoint Detection
An Isolation Forest anomaly detection model identifies endpoints exhibiting abnormal communication behavior.

### Anonymization Technology Detection
The system detects potential anonymization infrastructure including:
- Tor exit nodes
- VPN protocol usage
- Proxy server connections
- Encrypted tunnels

### Communication Graph Visualization
Network relationships between communicating entities are visualized using graph-based representations.

### Traffic Timeline Analysis
Communication events are plotted on a time-based timeline to help investigators correlate suspicious activity.

### Geolocation Mapping
External communication endpoints are mapped geographically using GeoIP location data.

### Automated Investigation Report
TRINETRA generates a structured investigation report summarizing analysis results and suspicious findings.

---

---

## Technology Stack

| Component | Technology |
|----------|-------------|
| Interface | Streamlit |
| Data Processing | Pandas |
| Network Analysis | Scapy |
| Machine Learning | Scikit-learn |
| Visualization | Plotly / NetworkX |
| Geolocation | GeoIP2 |
| Report Generation | ReportLab |
| Packet Capture | Tshark / Scapy |

---

## Authors
Developed as a cybersecurity research project focused on network metadata analysis and encrypted communication investigation.

TRINETRA is designed to support lawful digital forensic investigations by providing investigators with insights derived from observable network behavior.
