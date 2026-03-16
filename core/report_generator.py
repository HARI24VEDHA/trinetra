from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import datetime


def generate_soc_report(df, suspicious, filename="soc_report.pdf"):

    c = canvas.Canvas(filename, pagesize=letter)

    width, height = letter
    y = height - 50

    c.setFont("Helvetica-Bold", 18)
    c.drawString(50, y, "TRINETRA SOC Investigation Report")

    y -= 40
    c.setFont("Helvetica", 12)
    c.drawString(50, y, f"Generated: {datetime.datetime.now()}")

    y -= 30
    c.drawString(50, y, f"Total Packets: {len(df)}")

    y -= 20
    c.drawString(50, y, f"Unique Endpoints: {df['dst_ip'].nunique()}")

    y -= 20
    c.drawString(50, y, f"Unique Sources: {df['src_ip'].nunique()}")

    y -= 20
    c.drawString(50, y, f"Suspicious Endpoints Detected: {len(suspicious)}")

    y -= 40
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "Top Communication Flows")

    y -= 20
    c.setFont("Helvetica", 10)

    flows = df.groupby(["src_ip", "dst_ip"]).size().sort_values(ascending=False).head(5)

    for (src, dst), count in flows.items():

        line = f"{src} -> {dst}  |  Packets: {count}"

        c.drawString(50, y, line)

        y -= 15

    y -= 20

    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "Suspicious IPs")

    y -= 20
    c.setFont("Helvetica", 10)

    if suspicious is not None and not suspicious.empty:

        for ip in suspicious["ip"].head(5):
            c.drawString(50, y, f"Suspicious IP: {ip}")
            y -= 15
    else:
        c.drawString(50, y, "No suspicious activity detected.")

    c.save()

    return filename
