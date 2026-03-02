# The Trilogy of Death - Chapter I - Corel

| Field | Value |
|-------|-------|
| Platform | srdnlenIT2026 |
| Category | misc/forensics |
| Difficulty | Easy-Medium |

## Description
> He was born in a forgotten kingdom. In an era when the penguin still dreamed of conquering the desktop, a kingdom rose - beautiful, ambitious, and doomed.

## TL;DR
Corel Linux 1.2 disk image contains a WordPerfect macro (`/var/log/fc.wcm`) with XOR-encrypted flag. The stated key "FAKE" is a red herring. Known-plaintext attack using flag prefix `srdnlen{` recovers the real 4-byte XOR key `[0xBD, 0x4A, 0x6C, 0xEE]`.

## Initial Analysis

- `chall.zip` → `img.qcow` (QCOW2 v3, 5GB virtual)
- Partition 1: ext2, Corel Linux 1.2 (Debian 2.1 based)
- User: `davezero`, KDE desktop, WordPerfect 8 installed

## Vulnerability Identified

### WordPerfect Macro with XOR cipher (`/var/log/fc.wcm`)

The file is a plaintext WordPerfect Command Macro (WCM) that:

1. Computes key `kArr = [70, 65, 75, 69]` = `"FAKE"` via obfuscated arithmetic
2. Types the hint: `"The key is in what is left"`
3. XOR-decrypts `docbody[38]` with `kArr` and types the result
4. Computes `buf` from `rh[24]` XOR `kArr` but never outputs it

The XOR operation uses `(bb + kb) - 2*(bb & kb)` which equals `bb XOR kb`.

## Solution Steps

### Step 1: Identify the macro

Last-modified file on the filesystem: `/var/log/fc.wcm` (Feb 27 19:43 = same as FS last write time).

### Step 2: Understand the hint

"The key is in what is left" + key = "FAKE" → the key is fake, look elsewhere.

### Step 3: Known-plaintext attack

Flag format `srdnlen{` gives us 8 known plaintext bytes. XOR against `docbody[0..7]`:

```
docbody[0]=206 XOR 's'=115 → 189 (0xBD)
docbody[1]=56  XOR 'r'=114 → 74  (0x4A)
docbody[2]=8   XOR 'd'=100 → 108 (0x6C)
docbody[3]=128 XOR 'n'=110 → 238 (0xEE)
docbody[4]=209 XOR 'l'=108 → 189 (0xBD) ← repeats!
docbody[5]=47  XOR 'e'=101 → 74  (0x4A)
docbody[6]=2   XOR 'n'=110 → 108 (0x6C)
docbody[7]=149 XOR '{'=123 → 238 (0xEE)
```

4-byte repeating key: `[0xBD, 0x4A, 0x6C, 0xEE]`

### Step 4: Decrypt

```python
docbody = [206,56,8,128,209,47,2,149,202,34,95,128,226,41,92,156,
           142,38,51,153,137,57,51,218,211,21,88,130,201,121,30,128,
           137,62,93,152,142,55]
key = [0xBD, 0x4A, 0x6C, 0xEE]
flag = ''.join(chr(docbody[i] ^ key[i%4]) for i in range(len(docbody)))
print(flag)  # srdnlen{wh3n_c0r3l_w4s_4n_4lt3rn4t1v3}
```

## Flag
```
srdnlen{wh3n_c0r3l_w4s_4n_4lt3rn4t1v3}
```

## Key Lessons
- "FAKE" key is a deliberate red herring — always verify key validity
- Known-plaintext attacks on XOR with known flag format are trivial
- In forensics challenges, check last-modified timestamps to find planted files
- WordPerfect macros (.wcm) can contain obfuscated code

## Files

```
misc/trilogy/
├── chall.zip       # Original challenge archive
├── img.qcow        # Corel Linux 1.2 disk image
├── flag.txt         # Captured flag
└── solution.md      # This writeup
```
