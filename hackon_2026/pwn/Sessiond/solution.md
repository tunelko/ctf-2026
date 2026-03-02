# Sessiond - PWN Challenge

## Challenge Info
- **Name**: Sessiond
- **Category**: PWN
- **Remote**: `nc 0.cloud.chals.io 33543`
- **Description**: Sessiond es un daemon de gestión de datos de sesiones en su versión beta.
- **Flag**: `HackOn{st4ck_p1v0t&srop_is_2_ez_4_me}`

## Binary Analysis

```
chall: ELF 64-bit LSB pie executable, x86-64, stripped
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
```

Ubuntu 24.04, glibc 2.39. Four commands: `login`, `manage`, `status`, `exit`.

### Memory Layout (BSS)
| Address | Size | Purpose |
|---------|------|---------|
| 0x4060 | 16 | Username buffer |
| 0x4070 | 8 | Session pointer (set to &0x4080 in login) |
| 0x4080 | 0x210 | Session data buffer |
| 0x4290 | 4 | Size variable |

### Key Functions
- **login**: `read(0, 0x4060, 0x10)` then `printf("Logged in as %s", 0x4060)`
- **manage**: Asks for size (1-0x210), `fgets(0x4080, 0x210, stdin)`, `memcpy(stack_buf, 0x4080, size)`
- **status**: Uses raw `syscall` for write (contains hidden gadgets)

## Vulnerability

### 1. PIE Leak via Login
`login` reads exactly 16 bytes into `0x4060` with `read()` (no null terminator), then calls `printf("%s", 0x4060)`. Since `0x4070` holds a pointer to `0x4080` (PIE address), printf continues reading past the username into the pointer, leaking the PIE base.

### 2. Stack Buffer Overflow in Manage
`manage` has a stack buffer `s1` at `rbp-0x200` (512 bytes), but allows `size` up to `0x210` (528 bytes). The `memcpy(s1, global_buf, size)` copies 528 bytes to a 512-byte buffer, overflowing **16 bytes**: 8 bytes of saved RBP + 8 bytes of return address. No stack canary!

### 3. Hidden Gadgets in Status Function
The `status` function contains hidden byte sequences:
- `0x127c`: **`pop rax; ret`** (58 c3)
- `0x127e`: **`syscall; ret`** (0f 05 c3)
- `0x1392`: **`leave; ret`**

## Exploitation Strategy: Stack Pivot + SROP

### Step 1: Leak PIE
Login with 16 'A's → printf leaks the session pointer → compute PIE base.

### Step 2: Stack Pivot + Sigreturn
1. `manage` with size=0x210 writes ROP chain into global buffer at 0x4080
2. Overflow saved RBP = `global_buf` and return address = `leave;ret`
3. On return: `leave;ret` → second `leave;ret` pivots stack to global buffer
4. ROP chain: `pop rax(15)` → `syscall` (sigreturn) → kernel restores all registers from frame
5. Sigreturn frame sets: rax=59 (execve), rdi="/bin/sh", rsi=0, rdx=0, rip=syscall
6. Shell!

### Payload Layout in Global Buffer (0x4080)
```
[0x000] fake rbp (junk, consumed by leave)
[0x008] pop rax; ret
[0x010] 15 (SYS_rt_sigreturn)
[0x018] syscall; ret
[0x020] sigreturn frame (248 bytes)
[0x1a0] "/bin/sh\0"
[0x200] PIE_base + 0x4080 (pivot target = saved RBP)
[0x208] PIE_base + 0x1392 (leave;ret = return address)
```

## Exploit Script

See `solve.py`. Usage:
```bash
python3 solve.py           # LOCAL
python3 solve.py REMOTE    # REMOTE
python3 solve.py GDB       # DEBUG
```

## Key Takeaways
1. **PIE leak via adjacent memory**: `read()` without null terminator + `printf("%s")` leaks adjacent data
2. **Stack pivot via leave;ret**: Overwriting saved RBP + returning to `leave;ret` = stack pivot to controlled memory
3. **SROP (Sigreturn-Oriented Programming)**: With just `pop rax; ret` and `syscall; ret`, full register control via `rt_sigreturn`
4. **Hidden gadgets**: Misaligned instruction decoding reveals useful byte sequences (`pop rax; ret` at 0x127c was part of a `jmp` + other instructions)
5. **25% chance of null in leak**: When PIE base lower bits >= 0xC000, address carry creates null byte in position 1

## Files
- `solve.py` - Full exploit
- `sessiond/chall` - Challenge binary
- `sessiond/Dockerfile` - Ubuntu 24.04 environment
- `flag.txt` - Captured flag
