import hashlib

def extract_message_hashes(df):

    hashes = []

    if "payload" not in df.columns:
        return hashes

    for _, row in df.iterrows():

        payload = row["payload"]

        if payload:

            try:
                h = hashlib.sha256(str(payload).encode()).hexdigest()

                hashes.append({
                    "time": row["time"],
                    "src": row["src_ip"],
                    "dst": row["dst_ip"],
                    "hash": h[:32]
                })

            except:
                pass

    return hashes