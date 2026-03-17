# What is that browser doing?? — Rev


**CTF:** Midnight Flag CTF 2026
**Category:** Reverse Engineering
**Flag:** `MCTF{aimes_tu_les_gros_paffs_mon_bibouchou?}`

## TL;DR

Modified `surf` browser (suckless) with a hardcoded sbox-based substitution cipher. Invert the sbox lookup to recover the flag from the encrypted target stored in `b64encode`.

## Analysis

The binary is a patched version of [surf](https://surf.suckless.org/), a minimal WebKit/GTK browser. Three custom functions were added:

- **`little_encryption(ch)`** — substitution cipher using an sbox at `0xdfa0`
- **`b64encode()`** — stores 44 encrypted bytes into `secret_b64`, base64-encodes them, and sets them as a cookie value for `.midnightflag.fr`
- **`computeFlag()`** — prompts "What's your hidden secret?", encrypts input, base64-encodes, and prints it

### Encryption (little_encryption)

```c
// Pseudocode
int little_encryption(signed char ch) {
    int val = (int)ch;
    val = (val << 7) & 0xFFFF;
    val = (val * 0x539) >> 5;  // 0x539 = 1337
    val &= 0xFC;
    return sbox[val];
}
```

Each input byte maps to exactly one sbox output. The mapping is not injective for all 256 values but is unambiguous within printable ASCII when considering the flag format (uppercase `MCTF{` prefix, lowercase content, `}` suffix).

### Target ciphertext (from b64encode)

```
22 91 70 6a 64 43 5f fa bf 50 de 53 18 de 04 bf
50 de 65 c4 86 50 de ba 43 61 61 50 de fa 86 41
de 52 5f 52 86 18 71 e0 86 18 9c 20
```

Base64: `IpFwamRDX/q/UN5TGN4Ev1DeZcSGUN66Q2FhUN76hkHeUl9Shhhx4IYYnCA=`

## Solution

1. Extract the 256-byte sbox from offset `0xdfa0`
2. Build forward map: `little_encryption(c)` for all `c` in `[0..255]`
3. Invert the map to get `encrypted_byte -> plaintext_char`
4. Apply inverse map to the 44-byte target

```python
data = open('surf', 'rb').read()
sbox = data[0xdfa0:0xdfa0+256]

def little_encryption(ch):
    val = ch if ch < 128 else ch - 256
    val = (val << 7) & 0xFFFF
    val = (val * 0x539 >> 5) & 0xFC
    return sbox[val]

target = bytes([
    0x22,0x91,0x70,0x6a,0x64,0x43,0x5f,0xfa,
    0xbf,0x50,0xde,0x53,0x18,0xde,0x04,0xbf,
    0x50,0xde,0x65,0xc4,0x86,0x50,0xde,0xba,
    0x43,0x61,0x61,0x50,0xde,0xfa,0x86,0x41,
    0xde,0x52,0x5f,0x52,0x86,0x18,0x71,0xe0,
    0x86,0x18,0x9c,0x20,
])

from collections import defaultdict
rev = defaultdict(list)
for c in range(256):
    rev[little_encryption(c)].append(c)

flag = ''
for b in target:
    printable = [c for c in rev[b] if 32 <= c < 127]
    flag += chr(max(printable))  # uppercase for prefix, lowercase for body

print(flag)  # MCTF{aimes_tu_les_gros_paffs_mon_bibouchou?}
```

## Vulnerability

**CWE-321: Use of Hard-Coded Cryptographic Key** — The sbox, encryption algorithm, and encrypted flag are all embedded in the binary with no obfuscation beyond a simple substitution cipher.

## Key Lessons

- Custom substitution ciphers with static sboxes are trivially invertible
- The `1337` multiplier constant is a classic CTF hint
- When encryption output has collisions, flag format constraints (`MCTF{..}`) disambiguate
