from ipDetection import checkIp
from protocolDetection import checkProtocol
from applicationLayerDetection import checkApplicationProtocol
from alertModule import Alert
import re
from scapy.all import Packet, TCP, UDP, Raw
from typing import Optional
from scapy.layers.http import *
from portDetection import checkPort

class Rule:
    """ NIDS RULE """

    def __init__(self, data) -> None:
        """Below mentioned are mandatory"""
        self.action = data["ruleHeader"]["action"]
        self.protocol = data["ruleHeader"]["protocols"]
        self.sourceIP = data["ruleHeader"]["sourceIP"]
        self.destinationIP = data["ruleHeader"]["destinationIP"]
        self.sourcePort = data["ruleHeader"]["sourcePort"]
        self.destinationPort = data["ruleHeader"]["destinationPort"]
        self.direction = data["ruleHeader"]["direction"]
        self.sid = data["ruleHeader"]["sid"]

        # Allow ruleOptions to be None
        self.ruleOptions = data.get("ruleOptions", None)
        self.applicationLayer = data["ruleHeader"].get("applicationLayer", None)

    def match(self, pkt: Packet) -> bool:
        """
        Return True if and only if everything in the provided rule matches or else it will return False
        """

        # Application Layer
        if self.applicationLayer is not None:

            
            if not checkApplicationProtocol(self.applicationLayer, pkt):
                return False

            if self.applicationLayer.lower() == 'http':
                print("inside http ")
                print(pkt.summary())
                pktpayload = self.get_http_body(pkt)
                print("ohhhhhhhhhhhhhh gooooooooooooood",pktpayload)
                try:
                    
                    # #Take care of this IMPORTANT
                    # if not pkt.haslayer(HTTPRequest) or not pkt.haslayer(HTTPResponse): return False

                    
                    httpheader = self.ruleOptions.get("httpHeaders", None) if self.ruleOptions else None
                    httpbody = self.ruleOptions.get("httpBody", None) if self.ruleOptions else None

                    if httpheader is not None:

                        pktheader = self._get_headers(pkt)
                        ruleheaderName = httpheader.get("headerName")
                        ruleheaderValue = httpheader.get("headerValue")

                        if ruleheaderName not in pktheader or pktheader[ruleheaderName] != ruleheaderValue:
                            return False

                    if httpbody is not None:
                        pktpayload = self.__http_payload(pkt)
                        print("please god",pktpayload)
                        if pktpayload is None:
                            return False

                        content = httpbody.get("content", None)
                        regex = httpbody.get("regex", None)

                        if content is not None and content != pktpayload:
                            return False
                        if regex is not None and not re.search(regex, pktpayload):
                            return False
                except Exception as e:
                    print(f"Error processing HTTP packet: {e}")
                    return False

        # Transport Layer
        if not checkProtocol(self.protocol, pkt):
            return False
        
        check = checkPort(self.sourcePort,self.destinationPort,pkt)
        
        if not check:
            return False
        #By defaukt check for malware 

        
        # Matches PAYLOAD
        payload = self.ruleOptions.get("payloadDetectionOptions", None) if self.ruleOptions else None
        print("payload dict",payload)
        if payload is not None:
            pktpayload = self._process_tcp_payload(pkt)
            if pktpayload is None:
                return False
            print("payload dict",payload)
            content = payload.get("content", None)
            regex = payload.get("regex", None)
            if content is not None and content != pktpayload:
                return False
            print("regex",regex)
            if regex is not None and not re.search(regex, pktpayload):
                return False

        if not checkIp(self.sourceIP, self.destinationIP, pkt):
            return False
        return True

    def getEntireAlertMessage(self, pkt: Packet, ruleSid: int) -> str:
        """
        Based on the assumptions made in match we can directly get it to print IP layer and Transport Layer
        """
        # If there is some message to print 
        msg = "[USER DEFINED MSG] \n"
        msg += self.getMessageToPrint()
        print("before calling alert")
        alert = Alert()
        ipString = alert.ipString(pkt, ruleSid)
        tcpString = alert.tcpString(pkt, ruleSid) if pkt.haslayer(TCP) else ""
        udpString = alert.udpString(pkt, ruleSid) if pkt.haslayer(UDP) else ""

        httpHeader = ""
        httpBody = ""
        if self.applicationLayer is not None and self.applicationLayer.lower() == 'http':
            if pkt.haslayer(HTTPRequest) or pkt.haslayer(HTTPResponse):
                print("inside application layer")
                try:
                    httpHeader += alert.httpString(pkt, ruleSid)

                    httpBody += alert.httpBody(pkt,ruleSid)
                    print("httpBody",httpBody)
                except Exception as e:
                    print(f"Error processing HTTP alert: {e}")

        tcpPayload = "[TCP PAYLOAD]"
        udpPayload = "[UDP PAYLOAD]"

        if self.ruleOptions and self.ruleOptions.get("payloadDetectionOptions", None):
            tcpPayload += alert.tcpPayload(pkt, ruleSid) if pkt.haslayer(TCP) else ""
            udpPayload += alert.udpPayload(pkt, ruleSid) if pkt.haslayer(UDP) else ""

        completeAlertMessage = msg + "\n" + ipString + tcpString + udpString + httpHeader + httpBody + tcpPayload + udpPayload
        return completeAlertMessage

    def getMessageToPrint(self) -> str:
        if self.ruleOptions:
            return self.ruleOptions.get("msg", "")
        return ""

    def _process_tcp_payload(self, pkt: Packet) -> Optional[str]:
        if Raw in pkt:
            payload = pkt[Raw].load
            if isinstance(payload, bytes):
                try:
                    payload = payload.decode('utf-8', errors='ignore')
                except UnicodeDecodeError:
                    payload = str(payload)
            return payload
        else:
            return None

    def _process_udp_payload(self, pkt: Packet) -> Optional[str]:
        if Raw in pkt:
            payload = pkt[Raw].load
            if isinstance(payload, bytes):
                try:
                    payload = payload.decode('utf-8', errors='ignore')
                except UnicodeDecodeError:
                    payload = str(payload)
            return payload
        else:
            return None
    def _get_headers(self,pkt:Packet) -> dict:
        '''
        Extracts and returns HTTP headers as a dictionary.
        '''
        headers = {}
        if pkt.haslayer(HTTPRequest):
            layer = self.pkt.getlayer(HTTPRequest)
        elif pkt.haslayer(HTTPResponse):
            layer = self.pkt.getlayer(HTTPResponse)
        else:
            return None 
        
        for field_name, field_value in layer.fields.items():
            if field_name not in ['Method', 'Path', 'Http_Version', 'Status_Code', 'Reason_Phrase']:
                if isinstance(field_value, bytes):
                    field_value = field_value.decode('utf-8', errors='ignore')
                headers[field_name] = field_value

        return headers
    
    def __http_payload(self,pkt:Packet):
        if pkt.haslayer('HTTP'):
            http_payload = pkt['HTTP'].load 
            return http_payload
        return None
    
    def get_http_body(self,pkt: Packet) -> str:
        """
        Extracts the HTTP body from an HTTPRequest or HTTPResponse packet.
        """
        # Check if the packet has HTTPRequest or HTTPResponse layer
        if pkt.haslayer(HTTPRequest):
            http_layer = pkt[HTTPRequest]
        elif pkt.haslayer(HTTPResponse):
            http_layer = pkt[HTTPResponse]
        else:
            return None

        # Extract the payload (body) of the HTTP message
        body = http_layer.payload
        print(body)
        if isinstance(body, bytes):
            try:
                body = body.decode('utf-8', errors='ignore')
            except UnicodeDecodeError:
                body = str(body)
    
        return str(body)