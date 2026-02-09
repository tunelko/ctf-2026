# Pragyan CTF 2026 - Writeups

Writeups for challenges solved during Pragyan CTF 2026 (February 6-8, 2026).

**Challenges Solved:** 20/20
**Categories:** PWN, Web, Crypto, Forensics, Misc

---

## Table of Contents

- [PWN (4 challenges)](#pwn)
- [Web (7 challenges)](#web)
- [Crypto (4 challenges)](#crypto)
- [Forensics (4 challenges)](#forensics)
- [Misc (1 challenge)](#misc)

---

## PWN

| Challenge | Points | Solved | Writeup |
|-----------|--------|--------|---------|
| [Dirty Laundry](#dirty-laundry) | 200 | Feb 6, 2:12 PM | [English](dirty_laundry/WRITEUP_english.md) |
| [pCalc](#pcalc) | 200 | Feb 6, 2:17 PM | [English](pcalc/WRITEUP_english.md) |
| [Talking Mirror](#talking-mirror) | 200 | Feb 6, 6:39 PM | [English](talking_mirror/WRITEUP_english.md) |
| [TerViMator](#tervimator) | 289 | Feb 8, 12:01 AM | [English](TerviMator/WRITEUP_english.md) |

### Dirty Laundry
**Points:** 200 | **Category:** PWN

Binary exploitation challenge involving buffer overflow and ROP chain.

**Techniques:** Stack buffer overflow, ret2libc, ROP gadgets
**Flag:** `p_ctf{14UnDryHASbEenSUCces$fU11YCOMP1e73d}`

[📄 Writeup](dirty_laundry/WRITEUP_english.md) | [💻 Exploit](dirty_laundry/exploit.py)

---

### pCalc
**Points:** 200 | **Category:** PWN

Python jail escape via chained vulnerabilities.

**Techniques:** F-string AST bypass, object hierarchy exploitation, audit hook bypass
**Flag:** `p_ctf{CHA7C4LCisJUst$HorTf0rcaLCUla70r}`

[📄 Writeup](pcalc/WRITEUP_english.md) | [💻 Exploit](pcalc/exploit.py)

---

### Talking Mirror
**Points:** 200 | **Category:** PWN

Format string vulnerability with indirect write via RBP chain.

**Techniques:** Format string exploitation, RBP chain indirection, GOT overwrite
**Flag:** `p_ctf{7hETAlk!n6M!RR0RSpOkeONE7OOmANyT!m3S}`

[📄 Writeup](talking_mirror/WRITEUP_english.md) | [💻 Exploit](talking_mirror/solve.py)

---

### TerViMator
**Points:** 289 | **Category:** PWN

Virtual machine bytecode exploitation via sign extension bug.

**Techniques:** Sign extension exploit, arbitrary write, pointer patching
**Flag:** `p_ctf{tErVIm4TOrT-1000ha$BE3nd3feaT3D}`

[📄 Writeup](TerviMator/WRITEUP_english.md) | [💻 Exploit](TerviMator/exploit_aslr.py)

---

## Web

| Challenge | Points | Solved | Writeup |
|-----------|--------|--------|---------|
| [Domain Registrar](#domain-registrar) | 289 | Feb 6, 6:08 PM | [English](domain_registrar/WRITEUP_english.md) |
| [Shadow Fight](#shadow-fight) | 200 | Feb 7, 9:36 AM | [English](shadow_fight/WRITEUP_english.md) |
| [Shadow Fight 2](#shadow-fight-2) | 327 | Feb 7, 9:47 AM | [English](shadow_fight/WRITEUP_english.md) |
| [Note Keeper](#note-keeper) | 200 | Feb 7, 11:02 AM | [English](note_keeper/WRITEUP_english.md) |
| [Server OC](#server-oc) | 200 | Feb 7, 11:29 AM | [English](server_oc/WRITEUP_english.md) |
| [Picture This](#picture-this) | 279 | Feb 8, 10:21 AM | [English](picturethis/WRITEUP_english.md) |
| [Tac-Tic-Toe](#tac-tic-toe) | 200 | Feb 8 | [English](tac-tic-toe/WRITEUP_english.md) |

### Domain Registrar
**Points:** 289 | **Category:** Web

Domain registration service with SSRF vulnerability.

**Techniques:** SSRF, internal service access
**Flag:** `p_ctf{c@n_nEVer_%ru$T_D0M@!nS_FR0m_p0Ps}`

[📄 Writeup](domain_registrar/WRITEUP_english.md) | [💻 Exploit](domain_registrar/exploit.py)

---

### Shadow Fight
**Points:** 200 | **Category:** Web

XSS challenge with closed Shadow DOM bypass.

**Techniques:** Shadow DOM bypass, split-comment XSS, `window.find()` exploitation
**Flag:** `p_ctf{uRi_iz_js_db76a80a938a9ce3}`

[📄 Writeup](shadow_fight/WRITEUP_english.md) | [💻 Exploit](shadow_fight/exploit.py)

---

### Shadow Fight 2
**Points:** 327 | **Category:** Web

Advanced XSS with split-comment technique.

**Techniques:** Split-comment XSS (`/*` and `*/` in different params)
**Flag:** `p_ctf{admz_nekki_kekw_c6e194c17f2405c5}`

[📄 Writeup](shadow_fight/WRITEUP_english.md) | [💻 Exploit](shadow_fight/exploit_2.py)

---

### Note Keeper
**Points:** 200 | **Category:** Web

Next.js middleware bypass chain.

**Techniques:** CVE-2025-29927, CVE-2025-57822, middleware bypass
**Flag:** `p_ctf{Ju$t_u$e_VITE_e111d821}`

[📄 Writeup](note_keeper/WRITEUP_english.md) | [💻 Exploit](note_keeper/exploit.py)

---

### Server OC
**Points:** 200 | **Category:** Web

Multi-stage web exploitation chain.

**Techniques:** JWT alg=none bypass, prototype pollution, SSRF
**Flag:** `p_ctf{L!qU1d_H3L1um_$h0ulD_N0T_T0uch_$3rv3rs}`

[📄 Writeup](server_oc/WRITEUP_english.md) | [💻 Exploit](server_oc/exploit.py)

---

### Picture This
**Points:** 279 | **Category:** Web

JPEG polyglot with DOM clobbering.

**Techniques:** JPEG polyglot, DOM clobbering, CDN extension mismatch
**Flag:** `p_ctf{i_M!ss#d_Th#_JPG_5f899f05}`

[📄 Writeup](picturethis/WRITEUP_english.md) | [💻 Exploit](picturethis/solve.py)

---

### Tac-Tic-Toe
**Points:** 200 | **Category:** Web

WASM patching to defeat unbeatable AI.

**Techniques:** WebAssembly patching, minimax algorithm inversion
**Flag:** `p_ctf{W@sM@_!s_Fas&t_Bu?_$ecur!ty}`

[📄 Writeup](tac-tic-toe/WRITEUP_english.md) | [💻 Exploit](tac-tic-toe/solve.js)

---

## Crypto

| Challenge | Points | Solved | Writeup |
|-----------|--------|--------|---------|
| [Dora Nulls](#dora-nulls) | 200 | Feb 6, 5:55 PM | [English](dora_nulls/WRITEUP_english.md) |
| [R0tnoT13](#r0tnot13) | 200 | Feb 7, 9:42 AM | [English](R0tnoT13/WRITEUP_english.md) |
| [DumCows](#dumcows) | 200 | Feb 7, 12:11 PM | [English](dum_cows/WRITEUP_english.md) |
| [Candles and Crypto](#candles-and-crypto) | 200 | Feb 7, 5:23 PM | [English](candles_and_cripto/WRITEUP_english.md) |

### Dora Nulls
**Points:** 200 | **Category:** Crypto

Cryptographic puzzle involving null bytes.

**Techniques:** Null byte manipulation, custom cipher analysis
**Flag:** `p_ctf{th15_m4ps-w0n't_l3ads_2_tr34s3ure!}`

[📄 Writeup](dora_nulls/WRITEUP_english.md) | [💻 Exploit](dora_nulls/solve.py)

---

### R0tnoT13
**Points:** 200 | **Category:** Crypto

State reconstruction from XOR-rotation leaks.

**Techniques:** Linear algebra over GF(2), Z3 constraint solving, ROTL interpretation
**Flag:** `p_ctf{l1nyrl34k}`

[📄 Writeup](R0tnoT13/WRITEUP_english.md) | [💻 Exploit](R0tnoT13/solve_z3.py)

---

### DumCows
**Points:** 200 | **Category:** Crypto

XOR stream cipher with keystream reuse.

**Techniques:** Known-plaintext attack, keystream extraction
**Flag:** `p_ctf{Giv3_sm-H20-t0_C0WSS:./}`

[📄 Writeup](dum_cows/WRITEUP_english.md) | [💻 Exploit](dum_cows/solve.py)

---

### Candles and Crypto
**Points:** 200 | **Category:** Crypto

Polynomial hash zero attack for signature forgery.

**Techniques:** Polynomial hash collision, brute force suffix generation
**Flag:** `p_ctf{3l0w-tH3_c4Ndl35.h4VE=-tHe_CaK3!!}`

[📄 Writeup](candles_and_cripto/WRITEUP_english.md) | [💻 Exploit](candles_and_cripto/exploit.py)

---

## Forensics

| Challenge | Points | Solved | Writeup |
|-----------|--------|--------|---------|
| [Plumbing](#plumbing) | 200 | Feb 7, 10:27 AM | [English](plumbing/WRITEUP_english.md) |
| [$whoami](#whoami) | 400 | Feb 7, 11:39 AM | [English](whoami/WRITEUP_english.md) |
| [Epstein Files](#epstein-files) | 265 | Feb 7, 5:54 PM | [English](epstein_files/WRITEUP_english.md) |
| [c47chm31fy0uc4n](#c47chm31fy0uc4n) | 439 | Feb 8, 11:03 AM | [English](c47chm31fy0uc4n/WRITEUP_english.md) |

### Plumbing
**Points:** 200 | **Category:** Forensics

Docker forensics challenge.

**Techniques:** Docker layer analysis, file system forensics
**Flag:** `p_ctf{d0ck3r_l34k5_p1p3l1n35}`

[📄 Writeup](plumbing/WRITEUP_english.md)

---

### $whoami
**Points:** 400 | **Category:** Forensics

Network forensics with NTLMv2 hash cracking.

**Techniques:** NTLMv2 hash extraction, hashcat, timestamp analysis
**Flag:** `p_ctf{t.stark:Arcadia1451606400}`

[📄 Writeup](whoami/WRITEUP_english.md) | [💻 Exploit](whoami/exploit.py)

---

### Epstein Files
**Points:** 265 | **Category:** Forensics

PDF steganography and PGP decryption.

**Techniques:** PDF hidden data, XOR decryption, PGP symmetric encryption, ROT18
**Flag:** `p_ctf{41n7_n0_w4y_h3_5u1c1d3}`

[📄 Writeup](epstein_files/WRITEUP_english.md) | [💻 Exploit](epstein_files/solve.py)

---

### c47chm31fy0uc4n
**Points:** 439 | **Category:** Forensics

Memory forensics with Volatility3.

**Techniques:** Volatility3, memory dump analysis, process forensics, heap reconstruction
**Flag:** `p_ctf{heap_and_rwx_never_lie:1769853900:10.13.37.7:57540}`

[📄 Writeup](c47chm31fy0uc4n/WRITEUP_english.md)

---

## Misc

| Challenge | Points | Solved | Writeup |
|-----------|--------|--------|---------|
| [Lost in the Haze](#lost-in-the-haze) | 200 | Feb 8, 11:10 AM | - |

### Lost in the Haze
**Points:** 200 | **Category:** Misc

Miscellaneous challenge.

**Flag:** *[Flag not recorded]*

---

## Additional Challenges

These challenges were also solved but not listed in the scoreboard screenshot:

- **Crossing Boundaries** (Web) - HTTP Request Smuggling
  [📄 Writeup](crossing_boundaries/WRITEUP_english.md)

---

## Statistics

- **Total Points:** 4,685
- **Challenges Solved:** 20
- **Time Span:** February 6-8, 2026 (3 days)

### Points by Category

| Category | Challenges | Total Points |
|----------|-----------|--------------|
| PWN | 4 | 889 |
| Web | 7 | 1,695 |
| Crypto | 4 | 800 |
| Forensics | 4 | 1,304 |
| Misc | 1 | 200 |

### Solve Timeline

**Day 1 (Feb 6):** 6 challenges solved
**Day 2 (Feb 7):** 10 challenges solved
**Day 3 (Feb 8):** 4 challenges solved

---

## Tools & Techniques

### Most Used Tools
- **pwntools** - Binary exploitation
- **Z3 Solver** - Constraint solving
- **Volatility3** - Memory forensics
- **Burp Suite** - Web proxy
- **Hashcat** - Password cracking
- **WABT** - WebAssembly toolkit

### Key Techniques
- Format string exploitation
- ROP chains and return-to-libc
- Python jail escapes
- XSS and DOM manipulation
- SQL injection variants
- Cryptographic attacks
- Memory forensics
- WebAssembly reversing

---

## Repository Structure

```
pragyan_ctf/
├── README.md                    # This file
├── strucpoints.png             # Scoreboard screenshot
├── dirty_laundry/              # PWN challenges
├── pcalc/
├── talking_mirror/
├── TerviMator/
├── domain_registrar/           # Web challenges
├── shadow_fight/
├── note_keeper/
├── server_oc/
├── picturethis/
├── tac-tic-toe/
├── dora_nulls/                 # Crypto challenges
├── R0tnoT13/
├── dum_cows/
├── candles_and_cripto/
├── plumbing/                   # Forensics challenges
├── whoami/
├── epstein_files/
└── c47chm31fy0uc4n/
```

Each challenge directory contains:
- `WRITEUP.md` - Detailed writeup (Spanish)
- `WRITEUP_english.md` - Detailed writeup (English)
- `exploit.py` / `solve.py` - Working exploit code
- Challenge files and supporting materials

---

## About

These writeups document the solutions for Pragyan CTF 2026 challenges. All exploits were tested against live servers and flags verified.

**Note:** Some challenge names differ slightly between the scoreboard and directory names for filesystem compatibility.
