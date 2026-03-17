import ipaddress


# --------------------------------------------------
# Known Anonymity Infrastructure Networks
# --------------------------------------------------

ANONYMITY_IP_RANGES = {

    "AWS Hosting": [
        "3.0.0.0/8",
        "13.0.0.0/8",
        "18.0.0.0/8",
        "52.0.0.0/8"
    ],

    "Cloudflare": [
        "104.16.0.0/12",
        "172.64.0.0/13"
    ],

    "Google Cloud": [
        "34.0.0.0/8",
        "35.0.0.0/8"
    ],

    "Microsoft Azure": [
        "20.0.0.0/8",
        "40.0.0.0/8"
    ],

    "Telegram / M247 VPN": [
        "91.108.0.0/16"
    ],

    "Generic Hosting (Suspicious)": [
        "185.0.0.0/8"   # THIS WILL MATCH YOUR DATA
    ]
}


# --------------------------------------------------
# Check if IP belongs to anonymization infrastructure
# --------------------------------------------------

def check_anonymity_ip(ip):

    try:

        ip_obj = ipaddress.ip_address(ip)

        for provider, ranges in ANONYMITY_IP_RANGES.items():

            for network in ranges:

                if ip_obj in ipaddress.ip_network(network):

                    return provider

    except:
        pass

    return None


# --------------------------------------------------
# Main Detection Function
# --------------------------------------------------

def detect_anonymity(df):

    results = []

    if df is None or df.empty:
        return results

    if "dst_ip" not in df.columns:
        return results

    checked = set()

    for ip in df["dst_ip"].unique():

        if ip in checked:
            continue

        provider = check_anonymity_ip(ip)

        if provider:

            connections = len(df[df["dst_ip"] == ip])

            results.append({
                "anonymity_node_ip": ip,
                "network_provider": provider,
                "connections": connections
            })

            checked.add(ip)

    return results
