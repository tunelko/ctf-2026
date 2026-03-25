# nameme — PWN/RE

**CTF**: BSidesSF 2026
**Points**: 840
**Flag**: `CTF{i-need-a-dns-challenge-every-year}`

---

## TL;DR

Custom DNS server with stack buffer overflow in name parsing. The name buffer is 1024 bytes but no bounds check on accumulated label data. DNS compression pointers cause the parser to re-read labels, doubling buffer fill past the return address at offset 1064. ROP chain reads `/home/ctf/flag.txt` and writes it back via the UDP connection. Every 8th entry in the buffer has bytes 6-7 forced to `0x3F 0x2E` (label length byte + dot) — must be value entries, not gadget addresses.

---

## Binary

```
nameme: ELF 64-bit, statically linked, stripped
NX: enabled | Canary: No | PIE: No | Stack: NX
```

## Vulnerability: Name Parsing Buffer Overflow

Function at `0x401915`:
- Stack buffer `name_buf[1024]` at `rsp+0x10`
- Return address at `rsp+0x438` (offset **1064** from buffer)
- Labels are copied to buffer with `memcpy`, accumulating in `rbp` counter
- **No bounds check** on `rbp` against buffer size
- DNS compression pointer (`0xC0xx`) redirects parser to re-read earlier labels
- Labels can expand the buffer past 1024 bytes → overflow

The parser inserts a `.` (0x2E) between labels and a label length byte `0x3F` appears at every 64th position. These forced bytes corrupt entries 3, 11, 19, 27, 35... (every 8th from entry 3), specifically bytes 6-7 of each entry.

## Exploit Design

### Compression Pointer Trick

Packet layout:
- 12-byte DNS header
- 15 labels of 63 bytes + 1 label of 7 bytes = **968 bytes** in buffer (first pass)
- Compression pointer to offset 13 (re-reads label data as "virtual labels")
- Type/Class fields

The second pass re-reads the same labels, interpreting data[0]=0x3F as a virtual label length of 63. A `0x00` byte placed at label_data[441] terminates the second pass.

### Forced Byte Handling

At every 8th entry starting from entry 3, bytes 6-7 are forced to `0x3F 0x2E`. These entries MUST be small integer values (where high bytes don't matter since syscalls use 32-bit registers):

- Entry 3: `0` → rsi for O_RDONLY (esi = 0 ✓)
- Entry 11: `0` → rbx junk ✓
- Entry 19: `0` → rbx junk ✓
- Entry 27: `0` → absorbed by pop_rdi ✓
- Entry 35: `0` → absorbed by pop_rdi ✓

### ROP Chain

```
open("/home/ctf/flag.txt", 0)   → fd 6 (remote)
read(6, writable_bss, 256)
write(0, writable_bss, 256)     → sends back via UDP
exit(0)
```

Key gadgets (no PIE, statically linked):
- `pop rdi; ret` = 0x4028f0
- `pop rsi; ret` = 0x40fd82
- `pop rax; ret` = 0x43a257
- `pop rdx; pop rbx; ret` = 0x46abb7
- `syscall; ret` = 0x418842

The path string `/home/ctf/flag.txt` is pre-loaded from `host.list` at address `0x4a82e0`.

### FD Discovery

Remote fd layout: 0=stdin(socket), 3=host.list, 4=UDP socket, 5=dup. open() returns fd **6**. write to fd **0** sends data back through the UDP connection.

## Flag

```
CTF{i-need-a-dns-challenge-every-year}
```
