# Pragyan CTF 2026 - Writeups

Writeups for challenges solved during Pragyan CTF 2026 (February 6-8, 2026).

![Challenges Solved](challenges_solved.png)

```
pragyan_ctf_2026/                           20/20 · 5,888 pts
│
├── pwn/
│   ├── dirty_laundry/
│   │   ├── Binary exploitation with buffer overflow and ROP chain
│   │   ├── Learn: Stack buffer overflow, ret2libc, ROP gadgets
│   │   └── 📄 Writeup | 💻 Exploit
│   ├── pcalc/
│   │   ├── Python jail escape via chained vulnerabilities
│   │   ├── Learn: F-string AST bypass, object hierarchy, audit hook bypass
│   │   └── 📄 Writeup | 💻 Exploit
│   ├── talking_mirror/
│   │   ├── Format string vulnerability with indirect write via RBP chain
│   │   ├── Learn: Format string exploitation, RBP chain indirection, GOT overwrite
│   │   └── 📄 Writeup | 💻 Exploit
│   └── TerviMator/
│       ├── Virtual machine bytecode exploitation via sign extension bug
│       ├── Learn: Sign extension exploit, arbitrary write, pointer patching
│       └── 📄 Writeup | 💻 Exploit
│
├── web/
│   ├── domain_registrar/
│   │   ├── Domain registration service with SSRF vulnerability
│   │   ├── Learn: SSRF, internal service access
│   │   └── 📄 Writeup
│   ├── shadow_fight/
│   │   ├── XSS challenge with closed Shadow DOM bypass
│   │   ├── Learn: Shadow DOM bypass, split-comment XSS, window.find()
│   │   └── 📄 Writeup | 💻 Exploit
│   ├── shadow_fight_2/
│   │   ├── Advanced XSS with split-comment technique
│   │   ├── Learn: Split-comment XSS (/* and */ in different params)
│   │   └── 📄 Writeup | 💻 Exploit
│   ├── note_keeper/
│   │   ├── Next.js middleware bypass chain
│   │   ├── Learn: CVE-2025-29927, CVE-2025-57822, middleware bypass
│   │   └── 📄 Writeup | 💻 Exploit
│   ├── server_oc/
│   │   ├── Multi-stage web exploitation chain
│   │   ├── Learn: JWT alg=none bypass, prototype pollution, SSRF
│   │   └── 📄 Writeup | 💻 Exploit
│   ├── picturethis/
│   │   ├── JPEG polyglot with DOM clobbering
│   │   ├── Learn: JPEG polyglot, DOM clobbering, CDN extension mismatch
│   │   └── 📄 Writeup | 💻 Exploit
│   └── crossing_boundaries/  (solved out of time)
│       ├── HTTP Request Smuggling
│       ├── Learn: HTTP request smuggling
│       └── 📄 Writeup
│
├── crypto/
│   ├── dora_nulls/
│   │   ├── Cryptographic puzzle involving null bytes
│   │   ├── Learn: Null byte manipulation, custom cipher analysis
│   │   └── 📄 Writeup | 💻 Exploit
│   ├── R0tnoT13/
│   │   ├── State reconstruction from XOR-rotation leaks
│   │   ├── Learn: Linear algebra over GF(2), Z3 constraint solving, ROTL
│   │   └── 📄 Writeup | 💻 Exploit
│   ├── dum_cows/
│   │   ├── XOR stream cipher with keystream reuse
│   │   ├── Learn: Known-plaintext attack, keystream extraction
│   │   └── 📄 Writeup | 💻 Exploit
│   └── candles_and_cripto/
│       ├── Polynomial hash zero attack for signature forgery
│       ├── Learn: Polynomial hash collision, brute force suffix generation
│       └── 📄 Writeup | 💻 Exploit
│
├── forensics/
│   ├── plumbing/
│   │   ├── Docker forensics challenge
│   │   ├── Learn: Docker layer analysis, file system forensics
│   │   └── 📄 Writeup
│   ├── whoami/
│   │   ├── Network forensics with NTLMv2 hash cracking
│   │   ├── Learn: NTLMv2 hash extraction, hashcat, timestamp analysis
│   │   └── 📄 Writeup | 💻 Exploit
│   ├── epstein_files/
│   │   ├── PDF steganography and PGP decryption
│   │   ├── Learn: PDF hidden data, XOR decryption, PGP symmetric encryption, ROT18
│   │   └── 📄 Writeup | 💻 Exploit
│   └── c47chm31fy0uc4n/
│       ├── Memory forensics with Volatility3
│       ├── Learn: Volatility3, memory dump analysis, process forensics, heap reconstruction
│       └── 📄 Writeup
│
└── misc/
    ├── lost_in_the_haze/
    │   └── Miscellaneous challenge
    └── tac-tic-toe/
        ├── WASM patching to defeat unbeatable AI
        ├── Learn: WebAssembly patching, minimax algorithm inversion
        └── 📄 Writeup | 💻 Exploit
```

---

## Tools & Techniques

### Most Used Tools
- **pwntools** - Binary exploitation
- **Z3 Solver** - Constraint solving
- **Volatility3** - Memory forensics
- **Burp Suite** - Web proxy
- **Hashcat** - Password cracking
- **WABT** - WebAssembly toolkit

### Solve Timeline

**Day 1 (Feb 6):** 6 challenges solved
**Day 2 (Feb 7):** 10 challenges solved
**Day 3 (Feb 8):** 4 challenges solved
