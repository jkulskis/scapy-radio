from scapy.all import *
from scapy.layers.rftap import RFtap

def test_open_packets():
    pkts = rdpcap('test/rftap.pcap')
    # for pkt in pkts:
    #     pkt.show()
    pkts = [RFtap(bytes(pkt)) for pkt in pkts]
    for pkt in pkts:
        pkt.show()