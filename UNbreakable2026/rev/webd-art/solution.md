# webd-art (Cobweb Printer)

| Field       | Value                          |
|-------------|--------------------------------|
| Platform    | UNbreakable 2026               |
| Category    | reversing                      |
| Difficulty  | Hard                           |

## Description
> An experimental digital art collective presents a browser-only 'certificate canvas' that behaves like a procedural painting engine. Brushstrokes, stamps, and approval logic are woven together in a fragile cobweb of client-side checks inside WebAssembly.

## TL;DR
Dart2Wasm binary uses a Weyl-sequence PRNG with MurmurHash3 finalizer. The flag is XOR-encrypted with PRNG output and stored as a 40-byte array. The PRNG seed is derived from a 128-bit hash of the input, folded to 32 bits and passed through a splitmix32 finalizer. Brute-force the 32-bit seed using known flag format `CTF{...}`.

## Initial analysis

The challenge provides:
- `index.html` - UI with canvas, input field, render button
- `main.mjs` - Dart2wasm JS glue code (imports strings via `S: new Proxy({}, {get(_, prop) { return prop; }})`)
- `main.wasm` - 53,529 byte WasmGC binary with js-string builtins (import kind 0x42)

No standard tools (wabt, wasm-tools, V8, Node, Deno) can decompile or run this binary due to:
1. **WasmGC types** (struct type 0x50) - breaks wabt and wasm-tools
2. **js-string builtins** (import kind 0x42) - breaks all available runtimes including Chrome 145

Custom WASM parser and manual hex analysis required.

## Identified vulnerability

The validation is entirely client-side with a deterministic 32-bit PRNG seed, making it brute-forceable. The 128-bit hash folds to 32 bits, reducing the keyspace to 2^32.

## Solution process

### Step 1: Custom WASM parsing

Built `parse_wasm.py` to handle WasmGC types and extract:
- 371 string constants imported from module "S" (via JS Proxy pattern)
- 89 function imports (DOM/Canvas/JS APIs)
- Key strings: `^CTF\{[ -~]{8,80}\}$`, `CERTIFICATE UNLOCKED`, `XorShift32`

The "S" module uses a JS Proxy that returns the property name as the value:
```javascript
S: new Proxy({}, { get(_, prop) { return prop; } })
```

### Step 2: Manual disassembly of validation logic

Located validation code in the WASM binary via pattern matching on known constants.

**FNV-1a-32 hash** (offset 0x8105-0x8124) — used for canvas rendering, NOT for seed derivation:
```
hash = 0x811C9DC5
for byte in input: hash = (hash ^ byte) * 0x01000193
```

**128-bit hash** (offset 0x9012-0x901E): The actual seed derivation reads two i64 fields from a struct type[19], producing a 128-bit hash of the input. This is a Dart-internal hash function, not FNV.

**Hash verification** (offset 0x923D-0x926E): The two i64 hash components are XORed with expected constants:
- `hash_lo ^ 0x7C3D53C7EFBE9927`
- `hash_hi ^ 0x426EA238FB73B3AC`
Both must equal zero for the flag to be accepted.

**Seed derivation** (offset 0x9278-0x92D8): 128-bit hash folded to 32 bits + splitmix32 finalizer:
```
hash_mix = ((local2 ^ (local2 >> 32)) ^ (local3 ^ (local3 >> 32))) & 0xFFFFFFFF
v = (hash_mix ^ (hash_mix >> 16)) * 0x7FEB352D
v = (v ^ (v >> 15)) * 0x846CA68B
v = (v ^ (v >> 16))
seed = v if v != 0 else 0xC0FFEE42
```

**PRNG** (offset 0x930C-0x934D): Weyl sequence + MurmurHash3 32-bit finalizer:
```
state += 0x9E3779B9            # golden ratio constant (Weyl increment)
m = state ^ (state >> 16)
m = m * 0x85EBCA6B
m ^= m >> 13
m = m * 0xC2B2AE35
m ^= m >> 16
byte = m & 0xFF
```

**XOR validation** (offset 0x9352-0x9366): `flag[i] = prng_byte[i] ^ stored_array[i]`

### Step 3: Stored array extraction

Found `array.new_fixed type[6] count=40` at absolute offset 0x4e42. Decoded all 40 elements by parsing the WASM bytecode. Each element is either:
- A literal byte pushed via `i32.const N, i64.const VALUE, struct.new type[3]` (boxed Dart integer)
- A global reference via `global.get $gN` (7 positions reference globals 530-533)

The stored array with global placeholders:
```
[218, 78, 141, g530, 79, 33, 46, 234, 174, 75,
 g531, 130, 143, 169, 189, 93, 127, g531, g532, g533,
 239, 47, 94, 136, 89, 231, 203, 209, 88, g533,
 122, 147, 60, 167, 251, 224, g532, 100, 50, 163]
```

### Step 4: Brute-force 32-bit seed

Since `flag[0..2] = "CTF"` and `flag[39] = "}"`, the required PRNG bytes at these positions are fixed:
- prng[0] = 0x43 ^ 218 = 0x99
- prng[1] = 0x54 ^ 78 = 0x1A
- prng[2] = 0x46 ^ 141 = 0xCB
- prng[39] = 0x7D ^ 163 = 0xDE

Brute-forcing 2^32 seeds with early-exit filtering (C implementation):
- After byte 0: ~2^24 candidates eliminated per 2^8 tested
- After byte 1: ~2^16 remain
- After byte 2: ~2^8 remain
- After byte 39: **unique seed 0x13564e1d**

### Step 5: Recover unknown globals

With seed 0x13564e1d, generated all 40 PRNG bytes and XORed with known stored values to get a partial flag:

```
CTF?7h3_w3?_15_4_???_rng_15_d?73rm1n?5m}
```

Position 3 must be `{`, so g530 = prng[3] ^ 0x7B = **70**.

For the remaining globals (each appears at 2 positions), we need both positions to produce valid leet-speak characters:

| Global | Positions | Flag chars | Value |
|--------|-----------|------------|-------|
| g530   | 3         | `{`        | 70    |
| g531   | 10, 17    | `b`, `l`   | 4     |
| g532   | 18, 36    | `1`, `1`   | 198   |
| g533   | 19, 29    | `3`, `3`   | 150   |

The flag reads in leet-speak: **"the web is a lie, rng is determinism"**

Key insight: consistent leet encoding throughout — `e` is always `3`, `i` is always `1`. This resolved ambiguity between candidate flags (e.g., `l1e` vs `l13`).

### Step 6: Verification

The correct flag `CTF{7h3_w3b_15_4_l13_rng_15_d373rm1n15m}` was verified against the challenge platform and accepted.

## Discarded approaches

1. **Standard WASM tooling** (wabt, wasm-tools, wasm2wat): All fail on WasmGC struct types and import kind 0x42
2. **Runtime execution** (Node, Deno, Chrome 145): All fail on js-string builtins (import kind 0x42)
3. **FNV-1a-32 as seed source**: Initially assumed the FNV hash fed into seed derivation. After brute-forcing globals and failing hash verification, discovered FNV is used for canvas rendering only. The actual seed comes from a 128-bit Dart-internal hash.
4. **First flag candidate** `CTF{7h3_w3b_15_4_l1e_rng_15_de73rm1n15m}` (g533=192): Rejected by platform. The correct encoding uses consistent leet-speak (`e`→`3` everywhere).

## Final exploit

See `solve.py` (Python) and `bruteforce.c` (C, faster).

## Execution
```bash
# Python solver (slow but self-contained)
python3 solve.py

# C solver (fast, brute-forces full 2^32 seed space in ~30s)
gcc -O3 -o bruteforce bruteforce.c && ./bruteforce
```

## Flag
```
CTF{7h3_w3b_15_4_l13_rng_15_d373rm1n15m}
```

## Key Lessons
- WasmGC + js-string builtins (import kind 0x42) make ALL standard WASM tooling useless; manual binary analysis is the only option
- Dart2Wasm uses recognizable patterns: boxed integers (`struct.new type[3]`), arrays (`array.new_fixed type[6]`), string proxies via JS Proxy
- 32-bit PRNG seeds are trivially brute-forceable when output constraints are known (known-plaintext from flag format)
- Weyl sequence + MurmurHash3 finalizer is identifiable by constants: 0x9E3779B9, 0x85EBCA6B, 0xC2B2AE35
- Splitmix32 finalizer identifiable by: 0x7FEB352D, 0x846CA68B
- When multiple flag candidates exist, consistent encoding patterns (all leet-speak substitutions uniform) can disambiguate
- The FNV-1a-32 hash was a red herring for seed derivation — always trace the actual data flow rather than assuming
