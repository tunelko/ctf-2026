# pingpong — Writeup

**CTF:** 0xFun CTF 2026
**Category:** Reversing
**Points:** 50
**Difficulty:** Beginner
**Author:** blknova
**Flag:** `0xfun{h0mem4d3_f1rewall_305x908fsdJJ}`

> *"ONLY attempt if you love table tennis... you have been warned."*

---

## Summary

A Rust binary that implements a UDP "ping pong" server. The IP addresses it uses are not real IPs but rather ASCII encoding of the words "ping" and "pong" in dotted decimal notation. The flag is hardcoded as a hex string and encrypted with XOR using the concatenation of both "IPs" as a 30-byte key.

---

## Reconnaissance

```
$ file pingpong
ELF 64-bit LSB pie executable, x86-64, stripped (403 KB)

$ strings pingpong | grep -E '(flag|0xfun|hex|ping|pong|IP)'
0149545b5f4b5d1e5c545d1a55036c5700404b46505d426e02001b4909030957414a7b7a48
Invalid hex string.
112.105.110.103
112.111.110.103
IP Blocked!!! A personal message to :
```

The binary is Rust (~400 KB, typical of static Rust). It doesn't run as a conventional crackme but as a network service.

### Key Strings

| String | Meaning |
|--------|---------|
| `112.105.110.103` | ASCII of "ping": `chr(112)=p`, `chr(105)=i`, `chr(110)=n`, `chr(103)=g` |
| `112.111.110.103` | ASCII of "pong": `chr(112)=p`, `chr(111)=o`, `chr(110)=n`, `chr(103)=g` |
| `0149545b...7a48` | Encrypted flag (74 hex chars = 37 bytes) |
| `Invalid hex string` | Hex validation |
| `Now you're pinging the pong!` | Success message |
| `If you come to my table...` | Welcome message |

### Network Imports

```
socket, bind, recvfrom, sendto, getaddrinfo
```

The binary listens for UDP packets, receives "ping" (encoded as IP) and responds with "pong".

---

## Analysis

### The "IPs" Are Disguised Words

The central trick of the challenge is that the IP addresses are not real IPs -- they are the ASCII values of the letters written in IPv4 address format:

```
"ping" -> chr(112).chr(105).chr(110).chr(103) -> "112.105.110.103"
"pong" -> chr(112).chr(111).chr(110).chr(103) -> "112.111.110.103"
```

The challenge hint (*"table tennis"*) and the name (*"pingpong"*) point directly to this wordplay.

### Cyclic Key XOR Encryption

The flag is stored as a hex string in the `.rodata` section of the binary (offset `0xACEA`), just before the string `"Invalid hex string"`:

```
0149545b5f4b5d1e5c545d1a55036c5700404b46505d426e02001b4909030957414a7b7a48
```

37 bytes encrypted with XOR. The key is the **concatenation** of the two "IPs" as text strings:

```
Key = "112.105.110.103" + "112.111.110.103"
       <--- ping (15B) --->   <--- pong (15B) --->
Total length: 30 bytes, applied cyclically
```

The pattern is "ping pong ping pong..." -- back and forth like a table tennis match.

---

## Decryption

### Complete XOR Table

The encryption applies the 30-byte key cyclically over the 37 data bytes:

```
Bytes  0-14: XOR with "112.105.110.103" (ping) -> "0xfun{h0mem4d3_"
Bytes 15-29: XOR with "112.111.110.103" (pong) -> "f1rewall_305x90"
Bytes 30-36: XOR with "112.105." (ping, wrap) -> "8fsdJJ}"
```

| Pos | Encrypted | Key | Result |
|-----|-----------|-----|--------|
| 0 | `01` | ping `'1'` | `0` |
| 1 | `49` | ping `'1'` | `x` |
| 2 | `54` | ping `'2'` | `f` |
| 3 | `5b` | ping `'.'` | `u` |
| 4 | `5f` | ping `'1'` | `n` |
| 5 | `4b` | ping `'0'` | `{` |
| 6 | `5d` | ping `'5'` | `h` |
| 7 | `1e` | ping `'.'` | `0` |
| 8 | `5c` | ping `'1'` | `m` |
| 9 | `54` | ping `'1'` | `e` |
| 10 | `5d` | ping `'0'` | `m` |
| 11 | `1a` | ping `'.'` | `4` |
| 12 | `55` | ping `'1'` | `d` |
| 13 | `03` | ping `'0'` | `3` |
| 14 | `6c` | ping `'3'` | `_` |
| 15 | `57` | pong `'1'` | `f` |
| 16 | `00` | pong `'1'` | `1` |
| 17 | `40` | pong `'2'` | `r` |
| 18 | `4b` | pong `'.'` | `e` |
| 19 | `46` | pong `'1'` | `w` |
| 20 | `50` | pong `'1'` | `a` |
| 21 | `5d` | pong `'1'` | `l` |
| 22 | `42` | pong `'.'` | `l` |
| 23 | `6e` | pong `'1'` | `_` |
| 24 | `02` | pong `'1'` | `3` |
| 25 | `00` | pong `'0'` | `0` |
| 26 | `1b` | pong `'.'` | `5` |
| 27 | `49` | pong `'1'` | `x` |
| 28 | `09` | pong `'0'` | `9` |
| 29 | `03` | pong `'3'` | `0` |
| 30 | `09` | ping `'1'` | `8` |
| 31 | `57` | ping `'1'` | `f` |
| 32 | `41` | ping `'2'` | `s` |
| 33 | `4a` | ping `'.'` | `d` |
| 34 | `7b` | ping `'1'` | `J` |
| 35 | `7a` | ping `'0'` | `J` |
| 36 | `48` | ping `'5'` | `}` |

---

## Solver

```python
#!/usr/bin/env python3
"""
Solver for pingpong -- XOR with concatenated "ping" and "pong" IPs.
"""

enc = bytes.fromhex(
    "0149545b5f4b5d1e5c545d1a55036c57"
    "00404b46505d426e02001b4909030957"
    "414a7b7a48"
)

# The "IPs" are ASCII: 112.105.110.103 = "ping", 112.111.110.103 = "pong"
key = b"112.105.110.103" + b"112.111.110.103"  # 30 bytes

flag = bytes([d ^ key[i % len(key)] for i, d in enumerate(enc)])
print(flag.decode())
```

```
$ python3 solve.py
0xfun{h0mem4d3_f1rewall_305x908fsdJJ}
```

---

## Diagram

```
+-------------------------------------------------+
|                  pingpong (Rust)                |
|               UDP "ping pong" Server            |
|                                                 |
|  "112.105.110.103"  <->  chr(112,105,110,103)   |
|       = "ping" as decimal ASCII octets          |
|                                                 |
|  "112.111.110.103"  <->  chr(112,111,110,103)   |
|       = "pong" as decimal ASCII octets          |
|                                                 |
|  XOR Key = "112.105.110.103112.111.110.103"     |
|             <--- ping ---><--- pong --->        |
|               (30 bytes, cyclic)                |
|                                                 |
|  Encrypted flag (hex):                          |
|  0149545b5f4b5d1e5c545d1a55036c5700404b4650...  |
|                                                 |
|  flag[i] = enc[i] XOR key[i % 30]               |
+-------------------------------------------------+
```

---

## Key Concepts

### 1. ASCII as IPv4 Notation
The central idea is representing text as if it were an IP address. Each character is converted to its decimal ASCII value and separated with dots, identical to IPv4 format. It is a simple but initially effective obfuscation technique.

### 2. Cyclic Key XOR
A classic CTF encryption. The 30-byte key (ping IP + pong IP concatenated) repeats cyclically over the 37 data bytes. If the flag format (`0xfun{...}`) is known, the first 6 plaintext bytes are known and are sufficient to deduce the key.

### 3. Rust as Natural Obfuscation
The 400 KB Rust binary makes traditional static analysis difficult: thousands of runtime functions, name mangling, and no symbols. But `strings` reveals everything needed without even opening a disassembler.

---

## Alternative Solution: Known-Plaintext

Without even understanding the program, it can be solved using the known flag format:

```python
enc = bytes.fromhex("0149545b5f4b5d1e5c545d1a55036c57...")
known = b"0xfun{"

# Extract the first 6 bytes of the key
key_fragment = bytes([enc[i] ^ known[i] for i in range(len(known))])
print(key_fragment)  # b'112.10' -> clearly part of "112.105.110.103"
```

Seeing `112.10` as the key start immediately confirms the key is the "IP" of ping, and searching in strings reveals the complete key.

---

## Flag

```
0xfun{h0mem4d3_f1rewall_305x908fsdJJ}
```

---

## Tools Used

- **strings**: extraction of IPs, hex string and messages
- **Python 3**: XOR decryption
- **file**: Rust binary identification
