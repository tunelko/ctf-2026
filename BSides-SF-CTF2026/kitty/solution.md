# Kitty — BSidesSF 2026

**CTF**: BSidesSF 2026
**Category**: Misc / Terminal
**Author**: symmetric
**Flag**: `CTF{oh_no_your_terminal_spotted_me}`

---

## TL;DR

The file `/home/ctf/flag.kitty` contains a cat photo with the flag rendered as text, encoded using the **Kitty terminal graphics protocol**. Extract the file, parse the multi-chunk Kitty escape sequences, decode base64, decompress zlib, and render the 800x427 RGB pixel data as an image.

---

## Challenge Description

> I hide and only come out for certain terminals, can you find me?

The hint points to the **Kitty** terminal emulator, which supports its own [graphics protocol](https://sw.kovidgoyal.net/kitty/graphics-protocol/) for inline image display. The flag file uses this protocol to embed an image that only renders in Kitty-compatible terminals.

---

## Analysis

### File structure

The file is 759,436 bytes and contains Kitty graphics protocol escape sequences:

```
\x1b_G<params>;<base64_payload>\x1b\\
```

Split into 6 chunks (multi-part transfer with `m=1` for continuation, final chunk without `m` or `m=0`):

| Chunk | Header | Payload size |
|-------|--------|-------------|
| 1 | `a=T,q=2,f=24,o=z,m=1,s=800,v=427` | 131,072 B |
| 2-5 | `a=T,q=2,m=1` | 131,072 B each |
| 6 | `a=T,q=2` | 103,955 B |

### Parameters

- `a=T` — action: transmit and display
- `q=2` — quiet mode (no response)
- `f=24` — pixel format: 24-bit RGB
- `o=z` — compression: zlib
- `m=1` — more chunks follow
- `s=800` — image width: 800 pixels
- `v=427` — image height: 427 pixels

---

## Solve

```python
from pwn import *
import base64, zlib
from PIL import Image

io = remote('kitty-7c6c7969.challenges.bsidessf.net', 8024)
io.recvuntil(b'$ ')
io.sendline(b'base64 /home/ctf/flag.kitty')
time.sleep(10)

data = b''
while True:
    chunk = io.recv(timeout=2)
    if not chunk: break
    data += chunk
io.close()

# Parse base64 output → raw bytes
lines = data.decode(errors='replace').split('\n')
b64_str = ''.join(l.strip() for l in lines
                   if l.strip() and 'ctf@' not in l and 'base64' not in l)
while len(b64_str) % 4: b64_str += '='
raw = base64.b64decode(b64_str)

# Parse Kitty chunks: split on \x1b_G, extract payload after ';'
parts = raw.split(b'\x1b_G')
all_b64 = b''
for p in parts:
    if not p: continue
    semi = p.find(b';')
    if semi >= 0:
        payload = p[semi+1:]
        if b'\x1b' in payload:
            payload = payload[:payload.find(b'\x1b')]
        all_b64 += payload

# Decode and decompress
while len(all_b64) % 4: all_b64 += b'='
pixels = zlib.decompress(base64.b64decode(all_b64))

# Render as image
img = Image.frombytes('RGB', (800, 427), pixels)
img.save('flag_kitty.png')
```

The resulting image shows a kitten photo with the flag text overlaid:

**`CTF{oh_no_your_terminal_spotted_me}`**

---

## Key Lessons

- The **Kitty graphics protocol** uses APC escape sequences (`\x1b_G...;\x1b\\`) to embed images inline in terminal output
- Large images are split into multiple chunks using the `m=1` continuation flag
- The payload is base64-encoded, optionally zlib-compressed (`o=z`), raw pixel data
- Non-Kitty terminals silently ignore these escape sequences — the image is invisible unless you know to look for it
- When a challenge mentions "certain terminals", think Kitty, iTerm2, Sixel, or other image-capable terminal protocols
