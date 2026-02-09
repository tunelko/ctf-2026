# Epstein Files

**CTF/platform:** Pragyan CTF 2026

**Category:** Forensics

**Difficulty:** Medium-Hard

**Description:** Investigate the modified Epstein contacts PDF for hidden data.

**Remote:** N/A (file `contacts.pdf` + 95 JPGs)

**Flag:** `p_ctf{41n7_n0_w4y_h3_5u1c1d3}`

---

## Challenge Description

The following files are provided:

| File | Size | Description |
|---------|--------|-------------|
| `contacts.pdf` | 13,984,185 bytes | 95-page PDF with Jeffrey Epstein's contact list |
| `contacts-{1..95}_1.jpg` | ~150 KB each | 95 JPG images, one per PDF page |

The PDF is a modified version of the famous "Epstein Black Book" (public document from court case). The objective is to find the hidden flag.

## Analysis and Solution

### Step 1: Initial reconnaissance

```bash
file contacts.pdf
# contacts.pdf: PDF document, version 1.5
# 13,984,185 bytes (95 pages, 5393 objects)

pdfinfo contacts.pdf
# Creator: Draw (LibreOffice 25.2.7.2)
# Producer: LibreOffice 25.2
# Creation Date: 2026-02-01
# Pages: 95

# Internal structure
# 5393 PDF objects, 100 embedded images (95 pages + 3 SMask + 1 emoji + 1 SMask emoji)
# 12 embedded fonts (Arial, NotoSans, etc.)
# Pages 1-92: 1584x1224 px
# Pages 93-95: 1039x1344 px (different resolution!)
```

The PDF was created with **LibreOffice Draw 25.2.7.2**, indicating it was rebuilt by the challenge author (not the original case PDF). The creation date (2026-02-01) confirms it's a CTF file.

### Step 2: Search for anomalies in PDF structure

Exhaustive analysis of the PDF's internal structure looking for suspicious elements:

```bash
# Search for non-standard fields
strings contacts.pdf | grep -i hidden
# → % /Hidden (3e373f283d312d25222332362c3d2e292322)
```

We find a **commented** field in object 1730:

```
% /Hidden (3e373f283d312d25222332362c3d2e292322)
```

The `%` prefix in PDF specification indicates a comment. This means the `/Hidden` field is **ignored by all PDF readers** but is physically present in the raw bytes. A classic PDF steganography technique.

**Extracted hex value:** `3e373f283d312d25222332362c3d2e292322` (18 bytes)

### Step 3: Discover the XOR key

Pages 93-95 of the PDF have a different resolution from the rest (1039x1344 vs 1584x1224) and contain **black redaction boxes**. When examining with `pdftotext`, we discover that behind these redactions there is text rendered in near-white color (RGB ~0.925/0.984 on white background), invisible to the human eye but programmatically extractable:

```bash
pdftotext contacts.pdf - | tail -20
# ... (page 94 content)
# XOR_KEY
# JEFFREY
```

On page 94 we find hidden text: **"XOR_KEY"** and **"JEFFREY"**. This tells us "JEFFREY" is the key to apply XOR over the hex found in the previous step.

### Step 4: Decrypt the passphrase

Cyclic XOR of the hex with key "JEFFREY":

```python
hex_str = "3e373f283d312d25222332362c3d2e292322"
key = b"JEFFREY"
raw = bytes.fromhex(hex_str)
result = bytes([b ^ key[i % len(key)] for i, b in enumerate(raw)])
# → b'trynottogetdiddled'
```

| Hex    | Key | XOR  | Char |
|--------|-----|------|------|
| `0x3e` | `J` | `0x74` | `t` |
| `0x37` | `E` | `0x72` | `r` |
| `0x3f` | `F` | `0x79` | `y` |
| `0x28` | `F` | `0x6e` | `n` |
| `0x3d` | `R` | `0x6f` | `o` |
| `0x31` | `E` | `0x74` | `t` |
| `0x2d` | `Y` | `0x74` | `t` |
| ...    | ... | ...  | ...  |

**Passphrase obtained:** `trynottogetdiddled`

### Step 5: Discover PGP data after %%EOF

The PDF contains 109 additional bytes after the `%%EOF` marker:

```bash
python3 -c "
data = open('contacts.pdf','rb').read()
eof = data.rfind(b'%%EOF')
after = data[eof+5:].lstrip()
print(f'{len(after)} bytes')
open('/tmp/after_eof.bin','wb').write(after)
"
file /tmp/after_eof.bin
# PGP symmetric key encrypted data - AES with 256-bit key salted & iterated - SHA512
```

The `file` tool identifies the bytes as a **symmetrically encrypted PGP message** with:
- **Encryption:** AES-256 (CFB mode)
- **KDF:** S2K iterated & salted
- **Hash:** SHA-512

#### Detailed PGP structure

```
Offset 0x00: 8c 0d          → SKESK packet (tag 3, 13 bytes)
  04                         → Version 4
  09                         → AES-256
  03                         → S2K iterated+salted
  0a                         → SHA-512
  9a 72 58 bc e7 09 63 02   → Salt (8 bytes)
  f9                         → Count byte

Offset 0x0f: d2 5c          → SEIPD packet (tag 18, 92 bytes)
  01                         → Version 1
  [89 bytes encrypted data + MDC]
```

### Step 6: Decrypt the PGP message

```bash
echo "trynottogetdiddled" | gpg --batch --yes --passphrase-fd 0 \
    --decrypt /tmp/after_eof.bin
# → cpgs{96a2_a5_j9l_u8_0h6p6q8}
```

### Step 7: ROT13+ROT5 (final deobfuscation)

The decrypted text `cpgs{96a2_a5_j9l_u8_0h6p6q8}` is encoded with **ROT13** (letters) and **ROT5** (numbers), also known as ROT18:

```python
def rot13_rot5(text):
    result = []
    for c in text:
        if c.isalpha():
            base = ord('a') if c.islower() else ord('A')
            result.append(chr((ord(c) - base + 13) % 26 + base))
        elif c.isdigit():
            result.append(str((int(c) + 5) % 10))
        else:
            result.append(c)
    return ''.join(result)

rot13_rot5("cpgs{96a2_a5_j9l_u8_0h6p6q8}")
# → pctf{41n7_n0_w4y_h3_5u1c1d3}
```

| Original | Type  | Operation | Result |
|----------|-------|-----------|-----------|
| `c`      | letter | ROT13     | `p`       |
| `p`      | letter | ROT13     | `c`       |
| `g`      | letter | ROT13     | `t`       |
| `s`      | letter | ROT13     | `f`       |
| `9`      | digit| ROT5      | `4`       |
| `6`      | digit| ROT5      | `1`       |
| `a`      | letter | ROT13     | `n`       |
| `2`      | digit| ROT5      | `7`       |

**Leetspeak:** `41n7_n0_w4y_h3_5u1c1d3` → **"Ain't no way he suicided"**

Reference to the famous meme/conspiracy theory: "Epstein didn't kill himself".

---

## Complete decryption chain

```
PDF Object 1730 (commented field)
    │
    ▼
% /Hidden (3e373f283d312d25222332362c3d2e292322)
    │
    │  XOR with "JEFFREY" (key in hidden text page 94)
    ▼
trynottogetdiddled  (passphrase)
    │
    │  GPG decrypt (AES-256-CFB, SHA-512)
    ▼
109 bytes after %%EOF  ──────►  cpgs{96a2_a5_j9l_u8_0h6p6q8}
    │
    │  ROT13 (letters) + ROT5 (numbers)
    ▼
pctf{41n7_n0_w4y_h3_5u1c1d3}
    │
    │  Leetspeak
    ▼
"Ain't no way he suicided"
```

## Flag

```
p_ctf{41n7_n0_w4y_h3_5u1c1d3}
```

---

## Dead ends (rabbit holes)

Documenting what **didn't** work is as valuable as the solution. These are the approaches tried unsuccessfully:

### 1. Steganography in the 95 JPG images
- **steghide** with passwords: "trynottogetdiddled", "JEFFREY", "epstein", empty → nothing
- **stegseek** with rockyou.txt on all 95 images → no results
- **LSB analysis** (Least Significant Bit) of all images → LSB pixels are 0xFF (pure white), no hidden data
- **Post-FFD9 data**: Each JPG only has 1 extra byte (`\n`) after end marker → no appended data
- **zsteg** on PNG versions of the images → no findings

### 2. Advanced PDF analysis
- **SMask images** (alpha channels) from pages 93-95: Only contain a decorative border, no hidden information
- **Red emoji** (136x128 diamond in object 5287): Decorative image without steganographic data
- **731 instances of near-white text**: OCR artifacts from original scanned document, not intentionally hidden data
- **Embedded font analysis** (12 fonts, CMaps): No hidden data in mapping tables
- **Orphan objects**: No PDF objects without reference in catalog tree
- **JavaScript/EmbeddedFiles/Bookmarks**: Don't exist in the PDF
- **DocChecksum** (B917FB2632BD3A94067046828F06D3B7): Doesn't lead to anything useful

### 3. Incorrect decryption of post-EOF bytes
Before identifying them as PGP, multiple encryptions were tried:
- Single-byte XOR (0x00-0xFF, 256 combinations)
- Multi-byte XOR with keys: "trynottogetdiddled", "JEFFREY", "EPSTEIN", "p_ctf", PDF MD5/SHA hash
- RC4 with various keys
- AES-128/256 in ECB and CBC modes
- Openssl with ~20 different ciphers
- zlib/gzip decompression
- Base64 decode
- Known-plaintext attack assuming "p_ctf{" prefix
- Vigenere cipher

**Key lesson:** Using `file` on unknown binary data **before** trying manual decryptions would have saved hours of work.

### 4. Incident with qpdf
Ran `qpdf --replace-input contacts.pdf` to repair structure, which **deleted** both the `/Hidden` comment and post-EOF bytes from the original file. Fortunately, qpdf creates automatic backup at `contacts.pdf.~qpdf-orig`.

**Lesson:** Always work with copies. Never use `--replace-input` on forensic evidence files.

---

## Complete exploit

The automated exploit is at `/root/ctf/exploits/epstein_files.py`:

```bash
python3 epstein_files.py contacts.pdf
# [+] Hidden hex found: 3e373f283d312d25222332362c3d2e292322
# [+] Passphrase: trynottogetdiddled
# [+] Data after EOF: 109 bytes
# [+] PGP decrypted: cpgs{96a2_a5_j9l_u8_0h6p6q8}
# [+] ROT13+ROT5: pctf{41n7_n0_w4y_h3_5u1c1d3}
# FLAG: pctf{41n7_n0_w4y_h3_5u1c1d3}
```

---

## Tools Used

| Tool | Purpose |
|-------------|-----------|
| `file` | **Critical**: Identified post-EOF data as PGP instantly |
| `pdftotext` | Extract hidden text (page 94: XOR_KEY, JEFFREY) |
| `strings`/`grep` | Search for /Hidden field in raw PDF bytes |
| `gpg` | Decrypt symmetric PGP message (AES-256) |
| Python | XOR decryption, ROT13+ROT5, PDF structure analysis |
| `xxd`/`hexdump` | Raw byte and PGP packet structure analysis |
| `pdfinfo` | PDF metadata (creator, date, version) |
| `steghide`/`stegseek` | Failed image steganography attempts |
| `binwalk` | Search for embedded files (no results) |
| `qpdf` | PDF repair (caused data loss — see rabbit holes) |

## Lessons Learned

### PDF forensics techniques

1. **Always examine data after %%EOF.** The `%%EOF` marker is not necessarily the actual end of the file. Any additional bytes are suspicious and may contain encrypted data, embedded files, or even a complete second file. It's a classic PDF steganography technique.

2. **PDF comments (`%`) can hide data.** A field like `/Hidden` preceded by `%` is ignored by PDF readers and parsers but is physically present in the file. `strings` or `grep` find it, but tools like `qpdf` or `pdfparser` may remove it.

3. **`pdftotext` reveals invisible text.** Text rendered in near-white color (RGB ~0.925/0.984) on white background is invisible to the human eye in PDF readers, but `pdftotext` extracts it as plain text. Always run `pdftotext` as part of initial reconnaissance.

4. **Pages with different resolution are suspicious.** Pages 93-95 had different resolution (1039x1344 vs 1584x1224) and contained key clues. Anomalies in page or image dimensions are indicators of manipulation.

### General methodology

5. **Use `file` FIRST on unknown binary data.** The 109 post-EOF bytes were identified as PGP by `file` in one second. Time was wasted trying manual encryptions before running this basic command. **Always start with `file`.**

6. **ROT13+ROT5 (ROT18) is common CTF obfuscation.** When decrypted text has recognizable format but rotated letters (`cpgs{...}` ≈ `pctf{...}`), think ROT13 and extend to digits with ROT5.

7. **Thematic clues confirm the path.** The "Epstein Files" challenge produces "ain't no way he suicided" — thematic coherence indicates the solution is correct.

8. **Don't destroy evidence files.** `qpdf --replace-input` removed non-standard data from the PDF. In forensics, **always work with copies** and never modify the original file. Safe command: `cp file.pdf file_backup.pdf && qpdf file.pdf output.pdf`

### References

- [PDF Specification (ISO 32000-1)](https://www.iso.org/standard/51502.html) — Section 7.2.1 (General, Comment syntax)
- [OpenPGP Message Format (RFC 4880)](https://www.rfc-editor.org/rfc/rfc4880) — Section 5.3 (Symmetric-Key Encrypted Session Key Packets)
- [ROT13 / ROT5 / ROT47](https://en.wikipedia.org/wiki/ROT13) — Trivial substitution ciphers
- [Epstein "Black Book"](https://en.wikipedia.org/wiki/Jeffrey_Epstein#%22Black_book%22) — Public document from case
