from scapy.layers.http import *
def checkApplicationProtocol(protocol,pkt):
    '''
    Responsible to check whether the packet has the given application layer
    '''
    if (protocol.lower() == 'http' and  (pkt.haslayer(HTTPRequest) or pkt.haslayer(HTTPResponse))):
        return True
    return False 

