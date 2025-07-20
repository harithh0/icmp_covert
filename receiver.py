from scapy.all import *

fil = "src host 10.0.0.113 and icmp"

sniffed = sniff(filter=fil, prn=(lambda x: x[Raw]), count=20)
