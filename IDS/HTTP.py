from scapy.all import *
from scapy.layers.http import HTTPRequest, HTTPResponse, HTTP
from scapy.packet import Packet
from typing import Optional

class ApplHttp:
    def __init__(self, pkt: Optional[Packet] = None):
        '''
        Create instances of ApplHttp on top of HTTP instances to make analyzing HTTP packets faster.
        '''
        self.pkt = pkt

    def _determine_http_type(self) -> Optional[str]:
        '''
        Determine whether the packet is an HTTP request or response.
        '''
        if self.pkt.haslayer(HTTPRequest):
            return "HTTPRequest"
        elif self.pkt.haslayer(HTTPResponse):
            return "HTTPResponse"
        else:
            return None

    def get_payload(self,pkt) -> Optional[str]:
        '''
        To get the HTTP payload of a packet.
        Retrieves the body of an HTTP request or response.
        '''
        http_type = self._determine_http_type()
        if http_type == "HTTPRequest":
            layer = HTTPRequest
        elif http_type == "HTTPResponse":
            layer = HTTPResponse
        else:
            return None 

        if Raw in pkt[layer]:
            return pkt[layer][Raw].load.decode(errors='ignore')
        else:
            return None
        
    def get_headers(self) -> dict:
        '''
        Extracts and returns HTTP headers as a dictionary.
        '''
        headers = {}
        http_type = self._determine_http_type()
        if http_type == "HTTPRequest":
            layer = self.pkt.getlayer(HTTPRequest)
        elif http_type == "HTTPResponse":
            layer = self.pkt.getlayer(HTTPResponse)
        else:
            return None 
        
        for field_name, field_value in layer.fields.items():
            if field_name not in ['Method', 'Path', 'Http_Version', 'Status_Code', 'Reason_Phrase']:
                if isinstance(field_value, bytes):
                    field_value = field_value.decode('utf-8', errors='ignore')
                headers[field_name] = field_value

        return headers

    def get_body(self) -> Optional[str]:
        '''
        Extracts and returns the body of the HTTP request or response.
        '''
        http_layer = self._determine_http_type()
        if not http_layer:
            return None

        if http_layer == "HTTPRequest":
            layer = self.pkt[HTTPRequest]
        elif http_layer == "HTTPResponse":
            layer = self.pkt[HTTPResponse]
        else:
            return None

        body = layer.payload
        if isinstance(body, Raw):
            return body.load.decode('utf-8', errors='ignore')
        return None