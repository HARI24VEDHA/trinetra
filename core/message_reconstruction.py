# TRINETRA/core/message_reconstruction.py

from datetime import timedelta

class MessageReconstructor:

    def __init__(self, flows):
        self.flows = flows
        self.messages = []

    def detect_messages(self):
        """
        Detect possible encrypted message events
        based on packet bursts and size patterns
        """
        threshold = timedelta(seconds=2)

        for flow in self.flows:
            packets = flow["packets"]

            for i in range(1, len(packets)):
                prev_pkt = packets[i-1]
                curr_pkt = packets[i]

                diff = curr_pkt["time"] - prev_pkt["time"]

                if diff < threshold:
                    msg = {
                        "time": curr_pkt["time"],
                        "src": curr_pkt["src"],
                        "dst": curr_pkt["dst"],
                        "size": curr_pkt["size"]
                    }

                    self.messages.append(msg)

        return self.messages


    def summarize(self):
        sent = 0
        received = 0

        for msg in self.messages:
            if msg["src"].startswith("192.") or msg["src"].startswith("10."):
                sent += 1
            else:
                received += 1

        return {
            "messages_sent": sent,
            "messages_received": received,
            "total": len(self.messages)
        }
