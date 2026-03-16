from scapy.all import sniff
import pandas as pd
import time
from datetime import datetime

packets = []

def process_packet(packet):

    try:
        if packet.haslayer("IP"):

            packets.append({
               "time": datetime.now(),   # ADD TIMESTAMP
                "src_ip": packet["IP"].src,
                "dst_ip": packet["IP"].dst,
                "protocol": packet["IP"].proto,
                "length": len(packet)
            })

    except:
        pass


def capture_packets(interface="Wi-Fi", count=200):

    packets.clear()

    sniff(
        iface=interface,
        prn=process_packet,
        count=count,
        store=False
    )

    df = pd.DataFrame(packets)

    return df