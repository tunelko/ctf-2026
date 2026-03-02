#!/usr/bin/env python3
"""
UVT Crackme - Multi-stage reversing challenge solver
UniVsThreats26 Quals - Reversing
"""
import struct
import base64

# ===== STAGE 0: String comparison =====
stage0 = "UVT{"

# ===== STAGE 1: Generator builds "Kr4" =====
stage1 = "Kr4"

# ===== STAGE 2: Custom XOR/multiply check =====
# expected[i] = ((i*0x11 + 0x6d) ^ input[i]) + 0x13 + (i*7)
# Expected bytes = pack("<II", 0xfadc2431, 0xc5e42c25)
expected2 = struct.pack("<II", 0xfadc2431, 0xc5e42c25)
stage2 = ""
for i in range(8):
    target = expected2[i]
    c = ((target - 0x13 - (i * 7)) & 0xFF) ^ ((i * 0x11 + 0x6d) & 0xFF)
    stage2 += chr(c)
print(f"Stage 2: {stage2}")  # st4rG4te

# ===== STAGE 3: Custom check =====
# expected[i] = ((0xa7 - i*0xb) ^ input[i]) + i*3
# Expected bytes = pack("<II", 0xeda7d1d7, 0x49683954)
expected3 = struct.pack("<II", 0xeda7d1d7, 0x49683954)
stage3 = ""
for i in range(8):
    target = expected3[i]
    c = ((target - (i * 3)) & 0xFF) ^ ((0xa7 - i * 0xb) & 0xFF)
    stage3 += chr(c)
print(f"Stage 3: {stage3}")  # pR0b3Z3n

# ===== STAGES 4-5: VM + Extract (automatic, no input) =====
# Stage 4: VM bytecode interpreter executes 56-byte program
# Stage 5: Extracts embedded payload to uvt_crackme_work/stage2/

# ===== STAGE 6: Inline - contributes to flag automatically =====
# Partial flag from stages 0-6: UVT{Kr4cK_M3_N0w-cR4Km3_THEN-5T4rf13Ld_piNgS_

# ===== STAGE 7: Starfield Pings (5-bit decoder) =====
# Filter ttl=1337 entries, extract time values
times_1337 = [64, 65, 66, 67, 65, 68, 69, 70, 71, 66, 72, 73, 74, 75, 76]
indices = [t - 64 for t in times_1337]  # 5-bit values: 0-12

# Decode maps (split by value parity)
map_even_xor52 = bytes.fromhex("270d62612a1c7f3036343a383e3c2220")
even_map = bytes(b ^ 0x52 for b in map_even_xor52).decode()  # u_03xN-bdfhjlnpr

map_odd_rev_xor13 = bytes.fromhex("60627c7e787a74767072574749716341")
odd_map = bytes(b ^ 0x13 for b in map_odd_rev_xor13).decode()[::-1]  # RpbZTDacegikmoqs

stage7 = ""
for val in indices:
    if val % 2 == 0:
        stage7 += even_map[val // 2]
    else:
        stage7 += odd_map[(val - 1) // 2]
print(f"Stage 7: {stage7}")  # uR_pR0b3Z_xTND-

# ===== STAGE 8: Zen Log Fragments =====
# Order by slot, XOR fragx with k byte
zen_entries = [
    (1, 0x28, "7b7e1147657d79"),
    (2, 0x2f, "55771d435a771d"),
    (3, 0x36, "414164054650"),
]

combined = b""
for slot, k, fragx_hex in sorted(zen_entries):
    fragx = bytes.fromhex(fragx_hex)
    decoded = bytes(b ^ k for b in fragx)
    combined += decoded

combined_str = combined.decode()
stage8_b64 = base64.b64decode(combined_str).decode()
print(f"Stage 8 (logs, base64): {combined_str} -> {stage8_b64}")  # I_h1D3_in_l0Gz_

# ===== STAGE 9: Zen Void Islands =====
# zen_void.bin: two void ranges (A: 0x1000-0x7000 decoy, B: 0x9000-0xF000 real)
# Stage 8 (void): XOR with key 0x2a on island at 0xa1b2
stage8_void_island = bytes.fromhex("1b44755c1a1b6e75")
stage8_void_text = bytes(b ^ 0x2a for b in stage8_void_island).decode()
print(f"Stage 8 (void island): {stage8_void_text}")  # 1n_v01D_

# Stage 9: key = sum(stage8_void_text bytes) % 256
stage9_key = sum(stage8_void_text.encode()) % 256
print(f"Stage 9 key: 0x{stage9_key:02x}")  # 0x78

# Decode stage 9 island at 0xe3c4
stage9_island = bytes.fromhex("113627223d3605")
stage9_text = bytes(b ^ stage9_key for b in stage9_island).decode()
print(f"Stage 9 (void): {stage9_text}")  # iN_ZEN}

# ===== FULL FLAG =====
# Stages 0-6 produce the prefix via the crackme binary execution
prefix = "UVT{Kr4cK_M3_N0w-cR4Km3_THEN-5T4rf13Ld_piNgS_"
flag = prefix + stage7 + stage8_b64 + stage8_void_text + stage9_text
print(f"\nFLAG: {flag}")

# Inputs needed for wine execution:
print("\n--- Inputs for crackme.exe ---")
print(f"Stage 0: {stage0}")
print(f"Stage 1: {stage1}")
print(f"Stage 2: {stage2}")
print(f"Stage 3: {stage3}")
print("Stage 4-5: (automatic)")
print(f"Stage 7 fragment: {stage7}")
print(f"Stage 8 fragment: {stage8_b64}{stage8_void_text}{stage9_text}")
