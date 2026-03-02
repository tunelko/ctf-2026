# UVT Crackme

**Category:** Reversing
**Challenge:** Multi-stage crackme (PE64, 10 stages)
**Flag:** `UVT{Kr4cK_M3_N0w-cR4Km3_THEN-5T4rf13Ld_piNgS_uR_pR0b3Z_xTND-I_h1D3_in_l0Gz_1n_v01D_iN_ZEN}`

## Binary Analysis

```
$ file crackme.exe
crackme.exe: PE32+ executable (console) x86-64, for MS Windows, 15 sections
```

4.7MB PE64 binary. Main function at `0x140114280` contains a 10-case switch statement processing stages 0-9 sequentially. The flag is built incrementally from all stage outputs.

## Stage Breakdown

### Stage 0 — String Compare
`fcn.1401156f0`: Direct comparison with `"UVT{"` stored at `0x14030d7a0`.

### Stage 1 — Generator
`fcn.140115860` calls `fcn.140115aa0` which builds `"Kr4"` byte-by-byte (0x4b, 0x72, 0x34).

### Stage 2 — Custom XOR/Multiply Check
`fcn.140115b80`: For each byte i: `expected[i] = ((i*0x11 + 0x6d) ^ input[i]) + 0x13 + (i*7)`
Expected: `pack("<II", 0xfadc2431, 0xc5e42c25)` → **`st4rG4te`**

### Stage 3 — Custom Check
`fcn.1401164a0`: For each byte i: `expected[i] = ((0xa7 - i*0xb) ^ input[i]) + i*3`
Expected: `pack("<II", 0xeda7d1d7, 0x49683954)` → **`pR0b3Z3n`**

### Stage 4 — VM Execution
`fcn.140117780`: 56-byte bytecode VM interpreter. No input needed, produces flag fragment automatically.

### Stage 5 — Payload Extraction
`fcn.14011a330`: Extracts embedded artifacts to `uvt_crackme_work/stage2/`:
- `starfield_pings/pings.txt`
- `logs/system.log`
- `void/zen_void.bin`

### Stage 6 — Internal Processing
Inline in main. Processes extracted data and produces flag fragment. Combined stages 0-6 output: `UVT{Kr4cK_M3_N0w-cR4Km3_THEN-5T4rf13Ld_piNgS_`

### Stage 7 — Starfield Pings (5-bit Decoder)

File: `pings.txt` — Filter `ttl=1337` entries (15 pings). Time values = 5-bit indices (subtract 64).

Decoder maps (split by value parity):
- **Even map**: XOR `map_even_xor52` with 0x52 → `u_03xN-bdfhjlnpr`
- **Odd map**: XOR `map_odd_rev_xor13` with 0x13, then reverse → `RpbZTDacegikmoqs`

For each 5-bit value:
- Even value → `even_map[value/2]`
- Odd value → `odd_map[(value-1)/2]`

Result: **`uR_pR0b3Z_xTND-`**

### Stage 8 — Zen Log Fragments

File: `system.log` — 3 zen telemetry_rollup entries with `k` (XOR key) and `fragx` (XOR-masked hex).

Order by slot (1→2→3), XOR each `fragx` with its `k` byte:
- Slot 1 (k=0x28): `SV9oMUQ`
- Slot 2 (k=0x2f): `zX2luX2`
- Slot 3 (k=0x36): `wwR3pf`

Concatenated: `SV9oMUQzX2luX2wwR3pf` → Base64 decode → **`I_h1D3_in_l0Gz_`**

### Stage 8 (void) — Zen Void Island

File: `zen_void.bin` — 128KB file with two void ranges:
- Range A (0x1000-0x7000): Contains DECOY island
- Range B (0x9000-0xF000): Contains real islands

XOR island at 0xa1b2 with key 0x2a → **`1n_v01D_`**

### Stage 9 — Derived Key Island

Key = `sum(bytes("1n_v01D_")) % 256 = 0x78`

XOR island at 0xe3c4 with 0x78 → **`iN_ZEN}`**

(Island at 0x9d20 decodes to `iN_FAIL}` — the decoy)

## Exploit Script (solve.py)

```python
#!/usr/bin/env python3
"""UVT Crackme - Multi-stage reversing challenge solver"""
import struct, base64

# Stage 0: String comparison
stage0 = "UVT{"

# Stage 1: Generator builds "Kr4"
stage1 = "Kr4"

# Stage 2: Custom XOR/multiply check
expected2 = struct.pack("<II", 0xfadc2431, 0xc5e42c25)
stage2 = ""
for i in range(8):
    target = expected2[i]
    c = ((target - 0x13 - (i * 7)) & 0xFF) ^ ((i * 0x11 + 0x6d) & 0xFF)
    stage2 += chr(c)

# Stage 3: Custom check
expected3 = struct.pack("<II", 0xeda7d1d7, 0x49683954)
stage3 = ""
for i in range(8):
    target = expected3[i]
    c = ((target - (i * 3)) & 0xFF) ^ ((0xa7 - i * 0xb) & 0xFF)
    stage3 += chr(c)

# Stage 7: Starfield Pings (5-bit decoder)
times_1337 = [64, 65, 66, 67, 65, 68, 69, 70, 71, 66, 72, 73, 74, 75, 76]
indices = [t - 64 for t in times_1337]
map_even_xor52 = bytes.fromhex("270d62612a1c7f3036343a383e3c2220")
even_map = bytes(b ^ 0x52 for b in map_even_xor52).decode()
map_odd_rev_xor13 = bytes.fromhex("60627c7e787a74767072574749716341")
odd_map = bytes(b ^ 0x13 for b in map_odd_rev_xor13).decode()[::-1]
stage7 = ""
for val in indices:
    stage7 += even_map[val // 2] if val % 2 == 0 else odd_map[(val - 1) // 2]

# Stage 8: Zen Log Fragments (XOR + Base64)
zen_entries = [(1, 0x28, "7b7e1147657d79"), (2, 0x2f, "55771d435a771d"), (3, 0x36, "414164054650")]
combined = b""
for slot, k, fragx_hex in sorted(zen_entries):
    combined += bytes(b ^ k for b in bytes.fromhex(fragx_hex))
stage8_b64 = base64.b64decode(combined.decode()).decode()

# Stage 8 (void): XOR island at 0xa1b2
stage8_void = bytes(b ^ 0x2a for b in bytes.fromhex("1b44755c1a1b6e75")).decode()

# Stage 9: Derived key island
stage9_key = sum(stage8_void.encode()) % 256
stage9 = bytes(b ^ stage9_key for b in bytes.fromhex("113627223d3605")).decode()

# Full flag
prefix = "UVT{Kr4cK_M3_N0w-cR4Km3_THEN-5T4rf13Ld_piNgS_"
flag = prefix + stage7 + stage8_b64 + stage8_void + stage9
print(f"FLAG: {flag}")
```

## Key Lessons

- Multi-stage crackmes require methodical analysis of each stage function
- Embedded payloads (stage 5) can create additional artifacts needing separate analysis
- "5-bit decoder" with parity-split maps is an unusual but elegant encoding
- Decoy islands (DECOY tag, FAIL result) are red herrings to waste time
- Base64 encoding of XOR-decoded log fragments adds an extra layer
- The derived key chain (stage 8 text → stage 9 key) creates inter-stage dependencies
