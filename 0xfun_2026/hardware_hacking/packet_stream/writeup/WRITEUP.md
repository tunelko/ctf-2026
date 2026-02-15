# Packet Stream - DisplayPort Signal Recovery

## Challenge Info
- **Name**: Packet Stream
- **Category**: Hard Hack
- **Platform**: 0xFun CTF
- **Flag**: `0XFUN{8B10B_M1CRO_PACK3T_M4STER}`
- **Hint**: "flag is uppercase with the first being a zero and the rest being the letter o"
- **Description**: *We intercepted a raw signal capture from a DisplayPort display adapter. The data appears to be a single digitized frame from a 640x480 DisplayPort output.*

---

## Initial Reconnaissance

### Provided File

```
$ file signal.bin
signal.bin: data

$ wc -c signal.bin
2100021 signal.bin

$ xxd signal.bin | head -5
00000000: 6470 5f73 6967 6e61 6cc0 6368 6563 6b5f  dp_signal.check_
00000010: 656e 64c0 f4d0 430f 3de1 891e 6bac fae8  end...C.=...k...
00000020: a38f 3e2b b2b1 d862 0ad7 a3b0 c2f5 285c  ..>+...b......(\
```

**Header**: `dp_signal\xc0check_end\xc0` (20 bytes) — two strings separated by `0xC0`.

**Data**: 2,100,000 useful bytes (+ 1 trailing newline byte).

### The Mathematical Key

```
2,100,000 bytes × 8 bits / 10 bits_per_symbol = 1,680,000 symbols
1,680,000 / 4 bytes_per_pixel = 420,000 = 800 × 525
```

This matches **exactly** the standard 640×480 timing:
- H_TOTAL = 800 (640 active + 160 blanking)
- V_TOTAL = 525 (480 active + 45 blanking)
- 4 DisplayPort lanes

**Conclusion**: The data is encoded in **8b/10b at the bit level**, with 4 interleaved lanes.

---

## Phase 1: 8b/10b Decoding

### The Alignment Problem

8b/10b encodes each byte as 10 bits. To decode we need:
1. The correct **bit offset** (0-9)
2. The correct **bit order** (MSB/LSB first)
3. The correct **symbol order** (abcdeifghj vs jhgfiedcba)

### Decoding Table

The complete 8b/10b table was built with:
- 256 data characters × 2 disparities (RD+/RD-)
- 12 control characters (K28.0-K28.7, K23.7, K27.7, K29.7, K30.7)
- Total: **604 valid entries** out of 1024 possible 10-bit patterns

### Exhaustive Alignment Search

All combinations were tested: `rev_bytes × sym_reverse × offset` (2 × 2 × 10 = 40 configs):

```
rev_bytes=True,  sym_reverse=True,  offset=0 → 5000/5000 = 100.0% ✓
rev_bytes=True,  sym_reverse=False, offset=3 → 4692/5000 = 93.8%
rev_bytes=True,  sym_reverse=False, offset=4 → 4510/5000 = 90.2%
...
```

**Winning config**: `rev_bytes=True, sym_reverse=True, offset=0` → **100% valid symbols**.

### Result

```
Decoded 1,680,000 symbols
- Control chars: 36,852
- Data chars: 1,643,148
```

---

## Phase 2: DisplayPort Protocol Parsing

### Line Structure

Each line has **3200 symbols** (800 per lane × 4 interleaved lanes). Total: 525 lines.

```
Line 100 - Control positions:
[0-3]     : K.BC K.BC K.BC K.BC  → BS (Blanking Start) / FS (Fill Start)
[8-11]    : K.5C K.5C K.5C K.5C  → SS (Secondary Start)
[1136-39] : K.FB K.FB K.FB K.FB  → BE (Blanking End) - K27.7
[1392-95] : K.FE ×4              → FS (Fill Start) - K30.7  ┐ TU boundary
[1404-07] : K.F7 ×4              → FE (Fill End)   - K23.7  ┘
[1648-51] : K.FE ×4              → FS                       ┐ TU boundary
[1660-63] : K.F7 ×4              → FE                       ┘
... (every 256 symbols until position 3184-3199)
```

### Region Identification

- **Blanking/Fill** (positions 16-1135): Identical data across all 4 lanes
- **Transfer Units (TU)**: Every 256 symbols, marked by FS/FE
- **Stuff symbols**: 8 symbols between each FS/FE pair (TU overhead)
- **Pixel data**: Data bytes BETWEEN TU boundaries

### Pixel Data Regions Per Line

```python
pixel_regions = [(1152, 1392)]  # First region: 240 symbols
for i in range(7):               # 7 more regions of 240 each
    pixel_regions.append((1408 + i*256, 1408 + i*256 + 240))
# Total: 240 + 7×240 = 1920 bytes/line = 640 pixels × 3 bytes (RGB)
```

### Active Lines

```
Lines 0-34:   Vertical blanking (2 non-uniform groups → no pixel data)
Lines 35-514: Active video (480 lines, ~482 non-uniform groups)
Lines 515-524: Vertical blanking
```

---

## Phase 3: LFSR Scrambler Discovery

### The Problem

When rendering the pixel data directly as RGB 640×480, the result was **noise**. The data is scrambled with an LFSR (Linear Feedback Shift Register), standard in DisplayPort.

### Fill Data Analysis

The blanking (fill) data between BS and BE should be **known plaintext** (0x00). If `fill_scrambled = plaintext XOR lfsr_output`, and plaintext = 0x00, then **fill_data = lfsr_output directly**.

Verification: the fill data is **different on each line**, confirming that the LFSR runs continuously (DP 1.2+, no per-line reset).

### Failed Attempt: Standard Polynomial

The documented polynomial in the DP spec is `G(x) = x^16 + x^5 + x^4 + x^3 + 1`:

```
LFSR from 0xFFFF: ffff28c18a7cf923ae01...
Fill data lane0:  249c83ca2fb191113602...
→ NO MATCH
```

### Berlekamp-Massey to the Rescue

The **Berlekamp-Massey algorithm** was applied to the fill data bit sequence to discover the actual LFSR polynomial:

```python
# Convert fill data to bitstream (LSB first)
bits = []
for byte in fill_line35:
    for bit in range(8):
        bits.append((byte >> bit) & 1)

# Berlekamp-Massey → polynomial + degree
poly, degree = berlekamp_massey_gf2(bits)
```

**Result**:
```
LFSR degree: 16
Polynomial: x^0 + x^11 + x^12 + x^13 + x^16
→ G(x) = x^16 + x^13 + x^12 + x^11 + 1
```

This is the **reciprocal polynomial** of `x^16 + x^5 + x^4 + x^3 + 1` (exponents are "mirrored": 16-5=11, 16-4=12, 16-3=13).

**Verification**: 2224/2224 bits match (100%).

### LFSR State Reconstruction

```python
# LFSR state reconstructed from line 35 fill data
init_state = 0x2439  # Verified: generates exactly the fill data

# Reverse the LFSR back to the start of the frame
# (27,929 data bytes before line 35's fill)
frame_start_state = 0xFF00  # After reversing
```

---

## Phase 4: Descrambling and Rendering

### Descrambling Process

```python
# For each frame line:
#   1. Generate LFSR sequence (advances only for DATA, not CTRL)
#   2. XOR each data byte with the corresponding LFSR byte
#   3. All 4 lanes use the SAME LFSR sequence

for line in range(525):
    for symbol_group in range(0, 3200, 4):
        if is_data(symbol_group):
            for lane in range(4):
                descrambled = decoded[pos + lane] ^ lfsr_stream[lfsr_pos]
            lfsr_pos += 1  # One position per group (same key for 4 lanes)
```

### Final Result

Exactly **921,600 bytes** were extracted (640 × 480 × 3 RGB) and rendered as an image:

**Oprah meme** with the text:
- "YEAHHHH YOU FUCKING DID IT!"
- `0XFUN{8B10B_M1CRO_PACK3T_M4STER}`

---

## Key Lessons

1. **Math first**: The relationship `2,100,000 × 8/10 = 1,680,000 = 800 × 525 × 4` confirmed the encoding before writing a single line of code.

2. **Exhaustive alignment search**: 8b/10b has 40 possible bit ordering combinations. Only ONE yields 100% valid symbols.

3. **The reciprocal polynomial**: The LFSR used `x^16 + x^13 + x^12 + x^11 + 1` instead of the expected `x^16 + x^5 + x^4 + x^3 + 1`. They are mathematical reciprocals but produce completely different sequences.

4. **Berlekamp-Massey is essential**: Given an unknown LFSR, the fill data provides known-plaintext. BM recovers the minimal polynomial of any linear recurrent sequence in O(n²).

5. **Continuous LFSR (DP 1.2+)**: The scrambler does NOT reset per line. It runs continuously across the entire frame, requiring global state tracking.

6. **TU overhead**: Transfer Units add 8 stuff symbols every 256 symbols. Without removing them, the pixel data gets misaligned.

---

## Files

| File | Description |
|------|-------------|
| `signal.bin` | Original raw capture |
| `WRITEUP.md` | This writeup |
| `flag.txt` | Captured flag |
