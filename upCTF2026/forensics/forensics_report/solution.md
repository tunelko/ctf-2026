# 2025-Security-Report — upCTF 2026

**Category:** Forensics (PDF Steganography + Password Cracking)
**Flag:** `upCTF{V3ry_b4d_S3cUriTy_P0stUr3}`

## TL;DR

Security report PDF has an embedded encrypted `appendix.pdf`. Extract it, crack the weak RC4-128 password (`Maki`) with hashcat, read the flag.

---

## Analysis

### Main PDF (3 pages)

An "Internal Security Assessment Report" for the xSTF organization. The visible content is a generic security report with no apparent sensitive information.

Hints in the text:
- "sensitive supporting materials were **separated from primary reports**" → attached file
- "passwords that **don't follow basic password hygiene** principles" → weak password
- "legacy encryption mechanisms still in use" → RC4

### Embedded file

```
/Type /EmbeddedFile
/Subtype /application#2foctet-stream
/Filter /FlateDecode
/F (appendix.pdf)
```

The main PDF contains `appendix.pdf` as an embedded file (EmbeddedFile), compressed with FlateDecode.

### Attachment encryption

```
/Filter /Standard
/V 2          → RC4 variable-length key
/R 3          → Revision 3 (Acrobat 5-6)
/Length 128   → 128-bit RC4
/P -1028      → Permissions
/ID <09CEED129A1272DB85E35A35B9A9AFAC>
```

---

## Exploit

### Step 1: Extract appendix.pdf

```python
import zlib
with open("2025-Security-Report.pdf", "rb") as f:
    data = f.read()

idx = data.find(b"/Type /EmbeddedFile")
stream_start = data.find(b"stream\n", idx) + len(b"stream\n")
endstream = data.find(b"endstream", stream_start)
decompressed = zlib.decompress(data[stream_start:endstream].rstrip())
# → 15877 bytes, PDF 1.7, 1 page, encrypted
```

### Step 2: Crack password

```bash
# Hash format for hashcat mode 10500 (PDF 1.4-1.6)
$ cat hash.txt
$pdf$2*3*128*-1028*1*16*09ceed129a1272db85e35a35b9a9afac*32*93c8ea...00*32*b36a20...5d68

$ hashcat -m 10500 hash.txt --force -a 3 '?a?a?a?a' --increment
# Cracked in ~2 seconds
# Password: Maki
```

### Step 3: Decrypt

```bash
$ qpdf --password=Maki --decrypt appendix.pdf appendix_decrypted.pdf
# → upCTF{V3ry_b4d_S3cUriTy_P0stUr3}
```

---

## Key Lessons

1. **PDF embedded files**: PDFs can contain attached files that are not visible when rendered — always inspect with `strings` or parse the structure
2. **The report IS the hint**: the "findings" in the report itself describe exactly the vulnerabilities that need to be exploited (weak passwords, separated materials, legacy encryption)
3. **RC4-128 with short password**: hashcat mode 10500 cracks 4-char passwords in seconds

## References

- [PDF Reference — Embedded Files](https://opensource.adobe.com/dc-acrobat-sdk-docs/pdfstandards/PDF32000_2008.pdf)
- [Hashcat mode 10500](https://hashcat.net/wiki/doku.php?id=example_hashes)
