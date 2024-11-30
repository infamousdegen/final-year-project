from scapy.all import *
from scapy.all import UDP,TCP
import re
from scapy.layers.http import *
from ApplicationLayer import *


def checkPayload(payloadOptions, pkt):
    # print("siniede calling check payload ")
    payload = None

    if pkt.haslayer(TCP):
        payload = pkt[TCP].payload
    elif pkt.haslayer(UDP):
        payload = pkt[UDP].payload

    if isinstance(payload, NoPayload):
        return False

    content = payloadOptions.get("content", None)
    pattern = payloadOptions.get("regex", None)
    # print("inside pattern")
    # print(pattern)

    if content is not None:
        if isinstance(payload, Raw):
            return content.encode("utf-8") == payload.load

    elif pattern is not None:
        decoded = bytes(payload).decode('UTF-8','replace')
        # print("inside regex")
        print(pattern)
        print(decoded)
        try:
            match = re.search(pattern,decoded)
            if match:
                return True
        except re.error as e:
            print("Error occurred while searching:", e)
    return False




