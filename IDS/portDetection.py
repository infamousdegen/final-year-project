
from scapy.all import *
from scapy.all import TCP,UDP


def checkPort(srcPort:str,dstPort:str,pkt:Packet) -> bool:
    if pkt.haslayer(UDP):
        sourcePort = pkt[UDP].sport
        destPort = pkt[UDP].dport
    elif pkt.haslayer(TCP):
        sourcePort = pkt[TCP].sport
        destPort = pkt[TCP].dport
    else:
        print("Neither TCP nor UDP layer found in packet")
        return False
    def portsCheck(port, spec):
        if spec.lower() == 'any':
            return True
        else:
            return (str(port) == spec)
    sourcePortMatch = portsCheck(sourcePort, srcPort)
    destinationPortMatch = portsCheck(destPort,dstPort)
    
    if(not sourcePortMatch or not destinationPortMatch):
        return False
    return True
        