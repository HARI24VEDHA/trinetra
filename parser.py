import subprocess
import pandas as pd

TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"


def parse_pcap(file):

    command = [
        TSHARK_PATH,
        "-r", file,
        "-T", "fields",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "frame.protocols",
        "-e", "frame.len",
        "-e", "frame.time_epoch",
        "-E", "separator=,",
        "-E", "occurrence=f"
    ]

    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    output, error = process.communicate()

    lines = output.decode().splitlines()

    data = []

    for line in lines:

        parts = line.split(",")

        if len(parts) < 5:
            continue

        src, dst, protocol, length, time = parts[:5]

        try:
            length = int(length)
        except:
            length = 0

        try:
            time = float(time)
        except:
            continue

        data.append({
            "src_ip": src,
            "dst_ip": dst,
            "protocol": protocol,
            "length": length,
            "time": time
        })

    df = pd.DataFrame(
        data,
        columns=["src_ip", "dst_ip", "protocol", "length", "time"]
    )

    return df