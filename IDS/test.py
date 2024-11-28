from scapy.all import *
from scapy.all import IP
from netfilterqueue import NetfilterQueue

def print_packet(pkt):
    """Function to print the packet details."""
    scapy_pkt = IP(pkt.get_payload())  # Convert packet payload to Scapy packet
    print(scapy_pkt.summary())  # Print packet summary
    pkt.accept()  # Accept the packet

def main():
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, print_packet)  # Bind to queue 1 and use print_packet function to handle packets

    try:
        print("Listening to Netfilter Queue...")
        nfqueue.run()  # Start processing packets from queue
    except KeyboardInterrupt:
        pass
    finally:
        nfqueue.unbind()  # Unbind the queue
        print("Stopped listening to Netfilter Queue.")

if __name__ == "__main__":
    main()
