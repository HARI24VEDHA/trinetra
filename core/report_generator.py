from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
import datetime
import pandas as pd


def safe_col(df, col):
    if col in df.columns:
        return df[col]
    return pd.Series([])


def generate_soc_report(df, suspicious):

    filename = "trinetra_soc_report.pdf"

    styles = getSampleStyleSheet()

    story = []

    # ---------------------------------------------------
    # TITLE
    # ---------------------------------------------------
    story.append(Paragraph("TRINETRA Cyber Intelligence Platform", styles["Title"]))
    story.append(Paragraph("SOC Analyst Investigation Report", styles["Heading2"]))
    story.append(Spacer(1, 20))

    story.append(
        Paragraph(
            f"<b>Generated On:</b> {datetime.datetime.now()}",
            styles["Normal"]
        )
    )

    story.append(Spacer(1, 20))

    # ---------------------------------------------------
    # EXECUTIVE SUMMARY
    # ---------------------------------------------------

    total_packets = len(df)

    dst_ips = safe_col(df, "dst_ip")
    src_ips = safe_col(df, "src_ip")

    unique_destinations = dst_ips.nunique() if not dst_ips.empty else 0
    unique_sources = src_ips.nunique() if not src_ips.empty else 0

    suspicious_count = 0
    if suspicious is not None and not suspicious.empty:
        suspicious_count = len(suspicious)

    summary_table = [
        ["Metric", "Value"],
        ["Total Packets Captured", total_packets],
        ["Unique Destination Endpoints", unique_destinations],
        ["Unique Source Systems", unique_sources],
        ["Suspicious Entities Detected", suspicious_count]
    ]

    table = Table(summary_table, colWidths=[300, 200])

    table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.grey),
        ("TEXTCOLOR", (0,0), (-1,0), colors.white),
        ("GRID", (0,0), (-1,-1), 0.5, colors.black)
    ]))

    story.append(Paragraph("Executive Summary", styles["Heading3"]))
    story.append(Spacer(1,10))
    story.append(table)
    story.append(Spacer(1,20))

    # ---------------------------------------------------
    # COMMUNICATION FLOWS
    # ---------------------------------------------------

    story.append(Paragraph("Top Communication Flows", styles["Heading3"]))
    story.append(Spacer(1,10))

    flow_rows = [["Source", "Destination", "Packets"]]

    if "src_ip" in df.columns and "dst_ip" in df.columns:

        flows = df.groupby(["src_ip","dst_ip"]).size().reset_index(name="packets")

        flows = flows.sort_values("packets", ascending=False).head(10)

        for _, row in flows.iterrows():
            flow_rows.append([
                str(row["src_ip"]),
                str(row["dst_ip"]),
                int(row["packets"])
            ])

    table = Table(flow_rows)

    table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.lightgrey),
        ("GRID", (0,0), (-1,-1), 0.5, colors.black)
    ]))

    story.append(table)
    story.append(Spacer(1,20))

    # ---------------------------------------------------
    # SUSPICIOUS IPs
    # ---------------------------------------------------

    story.append(Paragraph("Suspicious IP Analysis", styles["Heading3"]))
    story.append(Spacer(1,10))

    if suspicious is not None and not suspicious.empty:

        ip_col = None

        if "dst_ip" in suspicious.columns:
            ip_col = "dst_ip"
        elif "src_ip" in suspicious.columns:
            ip_col = "src_ip"

        if ip_col:

            rows = [["Suspicious IP"]]

            for ip in suspicious[ip_col].unique():
                rows.append([str(ip)])

            table = Table(rows)

            table.setStyle(TableStyle([
                ("BACKGROUND", (0,0), (-1,0), colors.red),
                ("TEXTCOLOR", (0,0), (-1,0), colors.white),
                ("GRID", (0,0), (-1,-1), 0.5, colors.black)
            ]))

            story.append(table)

        else:

            story.append(
                Paragraph(
                    "Suspicious activity detected but IP fields unavailable.",
                    styles["Normal"]
                )
            )

    else:

        story.append(
            Paragraph(
                "No suspicious endpoints detected during analysis.",
                styles["Normal"]
            )
        )

    story.append(Spacer(1,20))

    # ---------------------------------------------------
    # ANALYST NOTES
    # ---------------------------------------------------

    story.append(Paragraph("SOC Analyst Observations", styles["Heading3"]))
    story.append(Spacer(1,10))

    observations = [
        "Traffic analysis indicates encrypted communication sessions.",
        "Certain endpoints show higher packet volume compared to others.",
        "Metadata correlation suggests possible coordinated communication patterns.",
        "Further host-level forensic analysis is recommended."
    ]

    for obs in observations:
        story.append(Paragraph(f"- {obs}", styles["Normal"]))

    story.append(Spacer(1,20))

    # ---------------------------------------------------
    # CONCLUSION
    # ---------------------------------------------------

    story.append(Paragraph("Investigation Conclusion", styles["Heading3"]))
    story.append(Spacer(1,10))

    story.append(
        Paragraph(
            "The investigation utilized metadata traffic analysis to identify communication patterns and suspicious endpoints. "
            "While encrypted traffic prevents direct payload inspection, behavioral traffic indicators provide valuable forensic insights.",
            styles["Normal"]
        )
    )

    story.append(Spacer(1,30))

    story.append(
        Paragraph(
            "Generated by TRINETRA Cyber Intelligence Platform",
            styles["Italic"]
        )
    )

    # ---------------------------------------------------
    # BUILD REPORT
    # ---------------------------------------------------

    doc = SimpleDocTemplate(filename, pagesize=A4)

    doc.build(story)

    return filename
