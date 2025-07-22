import logging
import os
import threading

from prompt_toolkit import PromptSession, print_formatted_text, prompt
from prompt_toolkit.patch_stdout import patch_stdout
from scapy.all import *

session = PromptSession()
# Silence only Scapy‐runtime warnings (leave other logs intact)
logging.getLogger("scapy.runtime").setLevel(
    logging.ERROR)  # or logging.CRITICAL


def sniff_icmp():

    def handle_recv(packet):
        if packet[ICMP].type == 0:
            return
        print_formatted_text("Message recieved:", packet[Raw].load)

    fil = "src host 10.0.0.212 and icmp"
    sniff(filter=fil, prn=handle_recv)


def handle_message():
    data_bytes = bytes([0x01] * 40)
    while True:
        data = session.prompt(">")
        key = 0x55
        full = "".join([str(hex(ord(c) ^ key)) for c in data])

        # the id comes from the current process id and doing a Internet checksum (used to identify the "session" or "process" sending the ping)
        icmp_id = os.getpid() & 0xFFFF
        # seq increments per sent packet, helps detect packet loss, track individual requests
        icmp_seq = 1

        icmp_packet = (IP(dst="10.0.0.212") / ICMP(id=icmp_id, seq=icmp_seq) /
                       Raw(load=data))
        counter = 0
        status = False
        while status is False:
            resp = sr1(icmp_packet, verbose=0, timeout=3)
            if counter > 3:
                break
            if resp:
                status = True
                break
            counter += 1


sniffing_thread = threading.Thread(target=sniff_icmp)
message_thread = threading.Thread(target=handle_message)
sniffing_thread.start()
message_thread.start()
