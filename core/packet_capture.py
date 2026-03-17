from scapy.all import sniff
import pandas as pd


def capture_packets(interface, packet_count):

    packets = sniff(iface=interface, count=packet_count)

    rows = []

    for pkt in packets:

        try:

            src_ip = None
            dst_ip = None
            src_port = None
            dst_port = None
            protocol = None

            if pkt.haslayer("IP"):
                src_ip = pkt["IP"].src
                dst_ip = pkt["IP"].dst

            if pkt.haslayer("TCP"):
                src_port = pkt["TCP"].sport
                dst_port = pkt["TCP"].dport
                protocol = "TCP"

            elif pkt.haslayer("UDP"):
                src_port = pkt["UDP"].sport
                dst_port = pkt["UDP"].dport
                protocol = "UDP"

            rows.append({
                "time": pkt.time,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
                "length": len(pkt),
                "payload": bytes(pkt).hex()
            })

        except:
            continue

    df = pd.DataFrame(rows)

    df["time"] = pd.to_datetime(df["time"], unit="s", errors="coerce")

    return df
