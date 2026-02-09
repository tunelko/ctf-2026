# Flag Canary - 247CTF Writeup

## Challenge Description
> Can you sneak the secret code past the canary hidden down the challenge mine?

## Analysis

The challenge provides a binary that implements a custom "canary" protection using RC4 encryption.

### Program Flow

1. Generate random 16-byte key from `/dev/urandom`
2. Initialize RC4 state with the key
3. Loop:
   - Clear buffer (56 bytes)
   - Generate canary using RC4 and place at buffer[32-47]
   - Read user input (up to 56 bytes)
   - Check if buffer[32-47] matches global canary AND buffer[48-55] == "247CTF:)"
   - If both pass, print flag

### Buffer Layout

```
[0-31]   : 32 bytes - User controlled
[32-47]  : 16 bytes - Canary (from RC4)
[48-55]  : 8 bytes  - Must be "247CTF:)" (secret code)
```

### Vulnerabilities

The RC4 implementation has **two critical bugs**:

1. **Index Reset Bug**: In `RC4_encrypt()`, the indices `i` and `j` are local variables that reset to 0 on every call. In proper RC4, these should be persistent state.

2. **XOR Swap Bug**: The `swap()` function uses XOR swap:
   ```c
   void swap(unsigned char *a, unsigned char *b) {
     *a ^= *b;
     *b ^= *a;
     *a ^= *b;
   }
   ```
   When `a == b` (same address), this zeros out the value instead of swapping.

### Exploitation

Due to these bugs, after ~750-1200 iterations:
- The S array degrades as entries get zeroed when i == j in the PRGA
- Eventually S[1..16] all become 0
- The RC4 keystream (canary) becomes **all zeros**

### Attack Strategy

1. Connect to server
2. Send 32 bytes repeatedly (~1500 times) to:
   - Preserve the canary at buffer[32-47] (not overwritten)
   - Advance the RC4 state
   - Fail the flag check (buffer[48-55] is zeros)
3. Once canary degrades to zeros, send:
   - 32 bytes padding
   - 16 bytes of `\x00` (matching the degraded canary)
   - "247CTF:)" (the secret code)
4. Both checks pass, flag is printed

## Solution

```python
from pwn import *

r = remote('host', port)
r.recvuntil(b'> ')

# Degrade the canary
for _ in range(1500):
    r.send(b'A' * 32)
    r.recvuntil(b'> ')

# Send exploit payload
payload = b'X' * 32 + b'\x00' * 16 + b'247CTF:)'
r.send(payload)
print(r.recvall())
```

## Flag

```
247CTF{553cd5XXXXXXXXXXXXXX634f40b2a352}
```

## Key Insight

The challenge name "canary_mine" hints at mining/digging through iterations. The XOR swap bug when `i == j` causes progressive degradation of the RC4 state, eventually making the canary predictable (all zeros). "Sneaking past" the canary means waiting until it degrades to a known value.
