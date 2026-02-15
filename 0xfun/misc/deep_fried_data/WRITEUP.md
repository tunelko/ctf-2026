# Deep Fried Data — Writeup

**CTF:** 0xFun CTF 2026
**Category:** Misc
**Points:** 250
**Difficulty:** Medium
**Flag:** `0xfun{d33p_fr13d_3nc0d1ng_0n10n}`

---

## Description

A file `notes.txt` is provided containing data encoded in multiple layers, like an onion of nested encodings and compressions.

## Analysis

The file `notes.txt` is encoded in hundreds of successive layers of different formats:

- **Text encodings:** Base64, Base32, Base85, ASCII85, Hex
- **Compressions:** gzip, bzip2, xz, lzma, zlib, zstd, lz4, deflate raw
- **Containers:** ZIP, TAR
- **Traps:** fake flags interspersed with `REAL_DATA_FOLLOWS:` markers indicating that decoding should continue

## Solution

The strategy is to automate format detection at each layer and apply the corresponding decoding/decompression in a loop, ignoring fake flags until reaching the real flag.

The script `solve.py` implements this logic:

1. Reads the data file
2. At each iteration, identifies the format by magic bytes or charset
3. Decodes/decompresses
4. If it finds text with `REAL_DATA_FOLLOWS:`, extracts the payload and continues
5. Detects `0xfun{...}` flags but doesn't stop until no more layers can be decoded
6. The final flag is the one that appears when there are no more layers

```bash
python3 solve.py
# [*] Start: ... bytes
# ...hundreds of layers...
# [FLAG layer N] 0xfun{d33p_fr13d_3nc0d1ng_0n10n}
```

## Flag

```
0xfun{d33p_fr13d_3nc0d1ng_0n10n}
```

## Files

- `notes.txt` — Original data (onion of encodings)
- `solve.py` — Solution script (automatic recursive decoding)
