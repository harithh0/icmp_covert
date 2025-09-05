import os

import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

with open("public.pem", "r") as f:
    public_key = rsa.PublicKey.load_pkcs1(f.read())

with open("private.pem", "r") as f:
    private_key = rsa.PrivateKey.load_pkcs1(f.read())

cipehertext = b"\xfa\xd8\xc4\x0ea\xda\xfb\xf1\xa2\xa2\xd1\x18\x86i1\x81\xb1.Fq\xffr\xb2\xef`\x0c\\\x90\x8aB|[\\\x1b9\x0f\xad\x8d\x9d\x87Y\x0f\xd1+J)%\xa4\x87<5\xff\xa5s\x15\x80q\x1f\x8en\xf2\x0cSc\xafUf\xe5\rtQ@\xc0\xb6c\x8aG\x04>i[\x80\x84\x9b_\xa4\x16\xa198\xda<T\xf8\x854\x86\xe2\xba\xbcy\xc3"

# -- sym --
with open("aes_key.bin", "rb") as key_file:
    symkey = key_file.read()

aesgcm = AESGCM(symkey)
# nonce = os.urandom(12)
# ciphertext = aesgcm.encrypt(nonce, message, associated_data=None)
# cipehertext = nonce + ciphertext

# extract nonce and ciphertext
nonce = cipehertext[:12]
enc_text = cipehertext[12:]

# decrypt
decrypted = aesgcm.decrypt(nonce, enc_text, associated_data=None)
print(decrypted)
