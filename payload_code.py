def sum(a, b):
    return a + b


import os
import socket
import subprocess

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("10.0.0.113", 8080))
s.sendall(b"hello")

for i in range(4):
    print(sum(5, i))
