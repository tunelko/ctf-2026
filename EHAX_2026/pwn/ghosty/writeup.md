# Ghosty

| Field       | Value                          |
|-------------|--------------------------------|
| Platform    | EHAXCTF 2026                   |
| Category    | pwn                            |
| Difficulty  | Medium-Hard                    |
| Points      | 467                            |
| Author      | -                              |

## Description
> How freaky can you get with the ghost?

## TL;DR
Multi-stage reversing challenge: LuaJIT FFI loads a Rust shared library (`libruntime.so`) that derives a key via HKDF/ChaCha20-Poly1305, decrypts and loads a second `.so` via `memfd_create`, which contains the actual verification logic. The correct input is the string `ghost_8d3f4a91c2e7b6d0`.

## Initial Analysis

### Provided Files
- `main.lua` — LuaJIT script defining API struct with FFI callbacks and calling `entry()`
- `libruntime.so` — Rust ELF64 x86-64 shared library (exports `entry`)
- `tables_blob.bin` — XOR-encoded lookup tables (1312 bytes)

### API Struct (packed)
```c
typedef struct __attribute__((packed)) {
    uint32_t abi_version;                              // +0x00
    uint32_t (*mix32)(uint32_t a, uint32_t b);         // +0x04
    void     (*scramble)(uint8_t *buf, size_t n, uint32_t seed); // +0x0c
    uint32_t (*get_salt)(void);                        // +0x14
    uint32_t (*policy)(uint32_t q);                    // +0x1c
    void     (*log)(const char *s);                    // +0x24
} API;
```

### Tables
XOR-decoded from `tables_blob.bin` with 32-byte nonce:
- **MIX_TABLE**: 256 x uint32 lookup table
- **POLICY_TABLE**: 256 bytes
- **SCRAMBLE_KEY**: 32 bytes

## Vulnerability Identified

### Type: Reversing / Multi-Stage Loader

Not a classic exploit but a multi-layer reversing challenge:
1. `entry()` in libruntime.so derives a key using Lua callbacks (mix32, policy, scramble)
2. Uses HKDF + ChaCha20-Poly1305 to decrypt an embedded blob in .rodata
3. The blob is a second .so loaded via `memfd_create` + `dlopen`
4. The stage2 contains `pulse()` which verifies the input against an expected value

## Solution Process

### Step 1: Instrumentation with C driver

LuaJIT was not available on the system. A C driver was written (`driver.c`) that replicates the Lua callbacks and calls `entry()` directly.

`LD_PRELOAD` was used with `intercept.so` to intercept `memfd_create` and `write()`, dumping the stage2 data to disk.

```bash
gcc -shared -fPIC -o intercept.so intercept.c -ldl
gcc -o driver driver.c -ldl
LD_PRELOAD=./intercept.so ./driver "AAAA"
```

Result: `stage2.so` dumped (15272 bytes, ELF64 shared object).

### Step 2: Stage2 analysis

`stage2.so` exports `catalog()` which returns a dispatch table. The real function is `pulse()` (2448 bytes, local symbol).

`pulse(api, input, n, output)`:
1. Copies max 32 bytes from input
2. Derives a key with 16 rounds of `mix32(salt ^ 0xa5c31d2e, i ^ 0x9e3779b9)` + `policy()`
3. Uses the key to decrypt 32 bytes from .rodata with xorshift PRNG
4. Compares input with decrypted bytes (SSE XOR + OR cascade)
5. If match, generates output (flag) and returns 0; otherwise returns 1

### Step 3: Expected value extraction

The 32 decrypted bytes are the string: `ghost_8d3f4a91c2e7b6d0` (20 bytes, null-padded to 32).

### Step 4: Verification

```bash
echo "ghost_8d3f4a91c2e7b6d0" | nc chall.ehax.in 22222
# Output: EH4X{fr3k7_fri3n5dly_1nt3rf4c35_0nc3_4g41n}
```

## Final Exploit

```bash
# Local
LD_PRELOAD=./intercept.so ./driver "ghost_8d3f4a91c2e7b6d0"

# Remote
echo "ghost_8d3f4a91c2e7b6d0" | nc chall.ehax.in 22222
```

## Flag
```
EH4X{fr3k7_fri3n5dly_1nt3rf4c35_0nc3_4g41n}
```

## Key Lessons
- When LuaJIT is not available, replicating the callbacks in C is viable
- `LD_PRELOAD` with hooks on `memfd_create`/`write` is effective for dumping stage2 binaries
- Key derivation was deterministic (fixed salt) — user input is only used in the final comparison, not in stage2 decryption
- The multi-stage loader (ChaCha20-Poly1305 -> memfd -> dlopen -> dlsym) adds complexity but no real security if keys are derivable
