# Double Face — VishwaCTF 2026 (Stego)

## TL;DR

PNG/ZIP polyglot file. A ZIP archive containing `secret.txt` with the flag is appended after the PNG IEND chunk.

## Solution

```bash
binwalk challenge.png
# Shows: PNG at 0x0, Zip archive at 0x46

unzip challenge.png
cat secret.txt
```

Or simply: `strings challenge.png | grep VishwaCTF`

## Flag

```
VishwaCTF{D0ubl3_F4c3_P0lygl0t_S3cr3t}
```

## Key Lessons

- "Two faces" = polyglot file (valid as both PNG and ZIP)
- The rockyou.txt password hint was a decoy — the ZIP had no password
- Always check for trailing data after file format endings (PNG IEND, JPEG FFD9)
- `binwalk` instantly reveals embedded archives
