from threading import Thread
from scapy.all import *
from scapy.all import IP
from Rule import Rule
from logModules import log_packet
from netfilterqueue import NetfilterQueue
from typing import List
from ratelimiter import RateLimiter
import redis
from detect_malware import load_malware_signatures,packet_callback

class Sniffer(Thread):
    """Thread responsible for sniffing and detecting suspect packet."""

    def __init__(self, ruleList: List[Rule],redis_host: str = 'localhost', redis_port: int = 6379, redis_db: int = 0, pcap_file=None):
        Thread.__init__(self)
        self.stopped = False
        self.ruleList = ruleList
        self.pcap_file = pcap_file
        self.redisinstance = redis.Redis(host=redis_host, port=redis_port, db=redis_db)
        #Implement the ratelimiter 
        self.ratelimit = RateLimiter(20,30,20,self.redisinstance)
        self.malwaresignature = load_malware_signatures('malware_signatures.json')

    def stop(self):
        self.stopped = True

    def stopfilter(self, x):
        return self.stopped

    def inPacket(self, pkt):
        """Directive for each received packet."""

        scapy_pkt = IP(pkt.get_payload())  
        # print(scapy_pkt.summary())
        #Do Preprocessing with the help of middle wares before 

        srcip = scapy_pkt.src
        # print("srcip",srcip)
        
        if self.ratelimit.isBlocked(srcip) or self.ratelimit.ratelimiting(srcip):
            print("dropping packets")
            pkt.drop()
        
        #check for malware by default

        elif packet_callback(scapy_pkt,self.malwaresignature):
            print("Dropping malicious packet")
            pkt.drop()
        # else:


        #     for rule in self.ruleList:
        #         matched = rule.match(scapy_pkt)

        #         if matched:
        #             print("Inside matching ")
        #             action = rule.action
        #             if action.lower() == 'alert':
        #                 messagetoAlert = rule.getEntireAlertMessage(scapy_pkt, rule.sid)
        #                 print("...............................................................................................")
        #                 print(messagetoAlert)
        #                 print("...............................................................................................")
        #             elif action.lower() == 'log':
        #                 log_packet(rule, scapy_pkt)
        #             elif action.lower() == 'drop':
        #                 print("Dropping packet inside drop function")
        #                 pkt.drop()
        #                 return  # Stop further processing, drop packet
        #             elif action.lower() == 'block':
        #                 pass
        #             else:
        #                 print("Not a valid action")

        pkt.accept()  # Accept the packet if not dropped
    def run(self):
        print("Sniffing started.")
        print("inside run function")
        nfqueue = NetfilterQueue()
        nfqueue.bind(1, self.inPacket)  # Bind to queue 1

        try:
            nfqueue.run()  # Start processing packets
        except KeyboardInterrupt:
            pass
        finally:
            nfqueue.unbind()
            print("Sniffing stopped.")
