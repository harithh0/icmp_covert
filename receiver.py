from scapy.all import *

fil = "src host 10.0.0.113 and icmp"
data_received = []


def handle_data_received(packet):
    data_received.append(packet[Raw].load)


sniffed = sniff(filter=fil, prn=handle_data_received, count=20)
print(data_received)
