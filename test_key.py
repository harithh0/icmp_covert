import os

import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

with open("public.pem", "r") as f:
    public_key = rsa.PublicKey.load_pkcs1(f.read())

with open("private.pem", "r") as f:
    private_key = rsa.PrivateKey.load_pkcs1(f.read())

message = b"lkdjflasfkjalsdkjfalsdfkjasldfkjlaskjdflaskjdfs"

# -- sym --
with open("aes_key.bin", "rb") as key_file:
    symkey = key_file.read()

aesgcm = AESGCM(symkey)
nonce = os.urandom(12)
ciphertext = aesgcm.encrypt(nonce, message, associated_data=None)
cipehertext = nonce + ciphertext

# extract nonce and ciphertext
nonce = cipehertext[:12]
enc_text = cipehertext[12:]

# decrypt
decrypted = aesgcm.decrypt(nonce, enc_text, associated_data=None)
print(decrypted.decode())
