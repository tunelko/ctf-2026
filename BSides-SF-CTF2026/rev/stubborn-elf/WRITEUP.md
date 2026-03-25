# stubborn-elf — BSidesSF CTF 2026

| Field | Value |
|-------|-------|
| **Category** | Forensics / RE |
| **Points** | 872 |
| **Author** | mrdebator |
| **Flag** | `CTF{3lf_h34d3rs_4r3_m3r3_sugg3st10ns}` |

## Description

> I tried to analyze this binary with readelf and objdump, but they just throw errors and crash! The binary runs perfectly fine though.

## TL;DR

ELF section header fields are corrupted to crash analysis tools. The binary still runs because the kernel only needs program headers. The flag is XOR-encoded with key `0x42` and appended after a `deadbeefcafebabe` marker at the end of the file.

## Analysis

### Corrupted ELF Header

```
$ file stubborn
ELF 64-bit LSB executable, x86-64, version 1 (SYSV), too many section (65535)

$ readelf -h stubborn
  Start of section headers:          18446744073709551615 (0xFFFFFFFFFFFFFFFF)
  Number of section headers:         65535 (0xFFFF)
```

Three fields in the ELF header are corrupted:

| Field | Offset | Value | Expected |
|-------|--------|-------|----------|
| `e_shoff` | 0x28 | `0xFFFFFFFFFFFFFFFF` | Valid offset |
| `e_shnum` | 0x3C | `0xFFFF` | ~31 |
| `e_shstrndx` | 0x3E | `0x1F` | Valid index |

This crashes `readelf` and `objdump` because they try to read 65535 section headers from an invalid offset. The binary still **runs perfectly** because the Linux kernel only uses **program headers** (segments) for execution — section headers are only needed by analysis tools.

### Fixing the Binary

Zero out the corrupted fields to make analysis tools work:

```python
data[0x28:0x30] = b'\x00' * 8  # e_shoff = 0
data[0x3C:0x3E] = b'\x00' * 2  # e_shnum = 0
data[0x3E:0x40] = b'\x00' * 2  # e_shstrndx = 0
```

### Main Function

After fixing, disassembly reveals a trivial `main`:

```asm
mov edi, 0x401178    ; "I am a very stubborn ELF. I hide my secrets well."
call puts
mov edi, 0x4011b0    ; "Try using readelf or objdump on me! I bet they crash."
call puts
xor eax, eax
ret
```

No flag in the code. The flag is hidden elsewhere.

### Finding the Flag

Examining the end of the file reveals a marker followed by encoded data:

```
Offset 0x3095: deadbeefcafebabe
Offset 0x309d: 01160439712e241d2a7176267130311d7630711d2f7130711d3137252571313673722c313f
```

### Decoding

The data is XOR-encoded. The key is determined from the known flag prefix `CTF{`:

```
0x01 XOR key = 0x43 ('C') → key = 0x42
0x16 XOR key = 0x54 ('T') → key = 0x42
0x04 XOR key = 0x46 ('F') → key = 0x42
0x39 XOR key = 0x7B ('{') → key = 0x42
```

Key = `0x42` (`'B'`). XOR all bytes:

```python
data = bytes.fromhex("01160439712e241d2a7176267130311d7630711d2f7130711d3137252571313673722c313f")
flag = bytes(b ^ 0x42 for b in data)
# → CTF{3lf_h34d3rs_4r3_m3r3_sugg3st10ns}
```

## Key Takeaways

- **ELF section headers are optional for execution** — the kernel loads segments via program headers (`PT_LOAD`), making section headers "mere suggestions" as the flag states
- **Corrupting `e_shoff`/`e_shnum`** is a simple anti-analysis trick that breaks standard tools but doesn't affect runtime
- **Fix**: zero out section header fields in the ELF header to restore tool compatibility
- **Hidden data at EOF** — always check beyond the last segment for appended payloads

## Files

- `stubborn` — original binary with corrupted headers
- `stubborn_fixed` — patched binary (section header fields zeroed)
- `flag.txt` — `CTF{3lf_h34d3rs_4r3_m3r3_sugg3st10ns}`
