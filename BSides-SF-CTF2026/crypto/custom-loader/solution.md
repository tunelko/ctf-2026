# Custom Loader - BSidesSF 2026 CTF

## Challenge Info
- **Category**: Reverse Engineering
- **Author**: mrdebator
- **Flag**: `CTF{fl4t_b1n4r13s_4r3_m3t4_c00l}`

## TL;DR
Kernel module `loader.ko` implements a custom `binfmt` handler that RC4-decrypts `.enc` files with key `BSIDES_SF_2026` before executing them as flat binaries. Decrypt `flag.enc` → get flag.

## Description
> I managed to exfiltrate a highly classified, encrypted executable, but no tool I throw at it can parse it. It doesn't even have an ELF header!
> Fortunately, I also managed to exfiltrate the custom Linux Kernel Module (loader.ko) that the target system uses to execute these files.

## Files
- `flag.enc` — 66 bytes, encrypted flat binary
- `loader.ko` — 364KB kernel module (ELF, x86-64, not stripped, with debug info)

## Analysis

### Identifying the module purpose
```bash
strings loader.ko | grep -i "format\|binary"
```
```
Private Binary format (.enc) registered.
Private Encrypted Binary Format
```

It's a Linux `binfmt` handler (custom binary format loader) for `.enc` files.

### Key functions
- `init_module` → calls `__register_binfmt`
- `load_encfile_binary` (1745 bytes) → main handler that decrypts and executes

### Reverse engineering `load_encfile_binary`

**Key extraction** (offsets 0x76-0x8f):
```asm
movabs rax, 0x535f534544495342  ; "BSIDES_S" (little-endian)
mov    [rsp+0x31], rax
movabs rax, 0x363230325f4653    ; "SF_2026\0" (little-endian)
mov    [rsp+0x38], rax
```
Combined string at `[rsp+0x31]`: **`BSIDES_SF_2026`** (14 bytes)

**RC4 KSA (Key Scheduling Algorithm)** (offsets 0x1c0-0x293):
1. S-box initialization: `S[i] = i` for i=0..255
2. Key mixing: `j = (j + S[i] + key[i % 14]) % 256; swap(S[i], S[j])`
   - Key length 14 confirmed by `imul edi, esi, 0xe` (multiply by 14 for modulo)
   - Magic constant `0x92492493` used for compiler-optimized division by 14

**RC4 PRGA** (offsets 0x2a2-0x37b):
- Standard RC4 keystream generation
- XOR at offset 0x36a: `xor eax, esi` decrypts each byte

### Decryption

```python
def rc4(key, data):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray()
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(byte ^ S[(S[i] + S[j]) % 256])
    return bytes(out)

key = b'BSIDES_SF_2026'
plaintext = rc4(key, open('flag.enc', 'rb').read())
```

### Decrypted binary
The result is a **flat x86-64 binary** (no ELF header — hence the custom loader):
```asm
mov eax, 1          ; syscall: write
mov edi, 1          ; fd: stdout
lea rsi, [rip+0x10] ; pointer to flag string
mov edx, 0x21       ; length: 33
syscall
mov eax, 60         ; syscall: exit
xor edi, edi        ; status: 0
syscall
; data: "CTF{fl4t_b1n4r13s_4r3_m3t4_c00l}\n"
```

## Flag
```
CTF{fl4t_b1n4r13s_4r3_m3t4_c00l}
```

## Key Lessons
- Linux `binfmt` handlers allow custom executable formats via kernel modules
- The module used RC4 (stream cipher) with a hardcoded key
- "Flat binaries" = raw machine code without ELF/PE headers, loaded directly into memory
- Not-stripped kernel modules with debug info make reversing much easier
- The magic number `0x92492493` is a compiler optimization for unsigned division by 14
