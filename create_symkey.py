import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Generate a random 256-bit (32-byte) AES key
key = AESGCM.generate_key(bit_length=256)

# Save it to a file
with open("aes_key.bin", "wb") as key_file:
    key_file.write(key)
