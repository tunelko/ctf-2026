#!/usr/bin/env python3
"""solve.py — Pokemon Emerald ROM hack CTF solver

Extracts the flag hidden as pixel art in a custom tilemap (Map 33).
The map is a 170x20 grid using only metatile 1 (off) and 4 (on),
forming 6-row-tall bitmap characters in rows 5-10.
"""
from pwn import *
import sys

context.log_level = "info"

rom_path = sys.argv[1] if len(sys.argv) > 1 else "files/chall.gba"
rom = read(rom_path)
log.info(f"ROM loaded: {len(rom)} bytes ({len(rom)/1024/1024:.1f} MB)")

# ============================================================
# STEP 1: Parse Map 33 header
# ============================================================
# The ROM hack injects custom map headers as an array at 0x4872A0.
# Each header is 28 bytes. Map 33 = 0x4872A0 + 33*28 = 0x48763C.
#
# Map header structure (28 bytes):
#   +0x00  u32  layout_ptr      → MapLayout struct
#   +0x04  u32  events_ptr
#   +0x08  u32  scripts_ptr
#   +0x0C  u32  connections_ptr
#   +0x10  u16  music_id
#   +0x12  u16  map_layout_id
#   ...

MAP33_HDR = 0x48763C
layout_ptr = u32(rom[MAP33_HDR : MAP33_HDR + 4])
# GBA ROM pointers use 0x08000000 base; subtract to get file offset
layout_off = layout_ptr - 0x08000000
log.info(f"Map 33 header @ 0x{MAP33_HDR:06X}")
log.info(f"  layout_ptr = 0x{layout_ptr:08X} → file offset 0x{layout_off:06X}")

# ============================================================
# STEP 2: Parse the MapLayout structure
# ============================================================
# MapLayout structure (16 bytes):
#   +0x00  u32  width
#   +0x04  u32  height
#   +0x08  u32  border_ptr
#   +0x0C  u32  map_data_ptr    → array of u16 metatile entries

width = u32(rom[layout_off : layout_off + 4])          # 170
height = u32(rom[layout_off + 4 : layout_off + 8])      # 20
map_data_ptr = u32(rom[layout_off + 12 : layout_off + 16])
map_data_off = map_data_ptr - 0x08000000                 # 0x481E6C

log.info(f"Layout @ 0x{layout_off:06X}: {width}x{height} = {width*height} metatiles")
log.info(f"  map_data_ptr = 0x{map_data_ptr:08X} → file offset 0x{map_data_off:06X}")
log.info(f"  map data occupies {width*height*2} bytes ({width*height} x u16)")

# ============================================================
# STEP 3: Read the metatile grid
# ============================================================
# Each metatile entry is u16 little-endian:
#   bits [0:9]   = metatile ID (0-1023)
#   bits [10:11] = collision
#   bits [12:15] = elevation/layer
#
# In this map, only two IDs are used:
#   1 = background (pixel OFF)
#   4 = foreground (pixel ON)
# This makes the tilemap a binary bitmap.

tiles = []
for i in range(width * height):
    off = map_data_off + i * 2
    tile_id = u16(rom[off : off + 2]) & 0x3FF  # lower 10 bits
    tiles.append(tile_id)

# Verify the binary nature
unique_ids = sorted(set(tiles))
log.info(f"Unique metatile IDs: {unique_ids}")
assert unique_ids == [1, 4], "Expected only metatile 1 (bg) and 4 (fg)"

# ============================================================
# STEP 4: Render the pixel art (rows 5-10)
# ============================================================
# The flag text is drawn in 6 rows (indices 5-10 of the 20-row map).
# Rows 0-4 and 11-19 are empty borders.

TEXT_ROWS = range(5, 11)  # 6 rows tall
FG_TILE = 4               # metatile 4 = pixel ON

log.info("Pixel art (rows 5-10, '#'=ON '.'=OFF):")
for row in TEXT_ROWS:
    line = ""
    for col in range(width):
        line += "#" if tiles[row * width + col] == FG_TILE else "."
    log.info(f"  R{row:02d}: {line}")

# ============================================================
# STEP 5: Segment into individual characters
# ============================================================
# Scan each column for any foreground pixel in the text rows.
# Contiguous groups of "active" columns form one character each,
# separated by all-background columns (the inter-character gap).

cols_active = []
for col in range(width):
    has_fg = any(tiles[row * width + col] == FG_TILE for row in TEXT_ROWS)
    cols_active.append(has_fg)

char_bounds = []  # list of (start_col, end_col)
in_char = False
start = 0
for col in range(width):
    if cols_active[col] and not in_char:
        start = col
        in_char = True
    elif not cols_active[col] and in_char:
        char_bounds.append((start, col))
        in_char = False
if in_char:
    char_bounds.append((start, width))

log.info(f"Found {len(char_bounds)} character groups")

# ============================================================
# STEP 6: Define glyph templates and match
# ============================================================
# Each glyph is defined as a set of (row, col) coordinates where
# pixels are ON, with (0,0) = top-left of the character's bounding box.
#
# These were extracted by rendering each character from the ROM
# and recording the ON-pixel positions. Each character is 6 rows tall
# (matching the 6 text rows) and 2-4 columns wide.
#
# AMBIGUITY NOTE — Two glyph shapes appear for multiple characters:
#
#   Circle:     .##.       Could be: O, o, 0
#               #..#       NPC hint "P.D. No hay ceros" (no zeros)
#               #..#       → Resolved as uppercase 'O'
#               #..#
#               .##.
#
#   Figure-8:   .##.       Could be: 3, e
#               #..#       In l33tspeak context: "d3oxys_4c3_3xplo1t"
#               ..#.       → Resolved as digit '3'
#               #..#
#               .##.

GLYPHS = {
    # === UPPERCASE (full height, starts at row 0 or 1) ===
    "H": {(0,0),(0,3),(1,0),(1,3),(2,0),(2,1),(2,2),(2,3),
           (3,0),(3,3),(4,0),(4,3),(5,0),(5,3)},               # w=4

    "O": {(1,1),(1,2),(2,0),(2,3),(3,0),(3,3),
           (4,0),(4,3),(5,1),(5,2)},                            # w=4, circle

    # === LOWERCASE (start at row 1-2, shorter) ===
    "a": {(2,1),(2,2),(3,0),(3,2),(4,0),(4,2),(5,1),(5,2)},    # w=3
    "c": {(2,1),(2,2),(3,0),(4,0),(5,1),(5,2)},                # w=3
    "d": {(1,2),(2,2),(3,1),(3,2),(4,0),(4,2),(5,1),(5,2)},    # w=3
    "k": {(1,0),(2,0),(3,0),(3,2),(4,0),(4,1),(5,0),(5,2)},    # w=3
    "l": {(1,0),(2,0),(3,0),(4,0),(5,0),(5,1)},                # w=2
    "n": {(2,0),(2,1),(2,2),(3,0),(3,3),(4,0),(4,3),(5,0),(5,3)},  # w=4
    "p": {(2,0),(2,1),(3,0),(3,2),(4,0),(4,1),(5,0)},          # w=3
    "t": {(1,1),(2,0),(2,1),(2,2),(3,1),(4,1),(5,1),(5,2)},    # w=3
    "v": {(2,0),(2,2),(3,0),(3,2),(4,0),(4,2),(5,1)},          # w=3
    "x": {(2,0),(2,2),(3,1),(4,0),(4,2),(5,0),(5,2)},          # w=3
    "y": {(2,0),(2,2),(3,0),(3,2),(4,1),(5,0)},                # w=3

    # === DIGITS ===
    "1": {(1,1),(2,0),(2,1),(3,1),(4,1),(5,0),(5,1),(5,2)},    # w=3
    "3": {(1,1),(1,2),(2,0),(2,3),(3,2),(4,0),(4,3),(5,1),(5,2)},  # w=4, figure-8
    "4": {(1,1),(1,2),(2,0),(2,2),(3,0),(3,1),(3,2),(3,3),
           (4,2),(5,2)},                                        # w=4
    "5": {(1,0),(1,1),(1,2),(1,3),(2,0),(3,0),(3,1),(3,2),
           (4,3),(5,0),(5,1),(5,2)},                            # w=4

    # === PUNCTUATION ===
    "{": {(1,1),(1,2),(2,1),(3,0),(4,1),(5,1),(5,2)},          # w=3
    "}": {(1,0),(1,1),(2,1),(3,2),(4,1),(5,0),(5,1)},          # w=3
    "_": {(5,0),(5,1),(5,2)},                                   # w=3, only bottom row
}


def extract_bitmap(start_col, end_col):
    """Extract the set of (row, col) ON-pixel positions for a character,
    where row is relative to TEXT_ROWS[0] and col relative to start_col."""
    pts = set()
    for row_idx, row in enumerate(TEXT_ROWS):
        for c in range(start_col, end_col):
            if tiles[row * width + c] == FG_TILE:
                pts.add((row_idx, c - start_col))
    return pts


def match_glyph(bitmap):
    """Match a bitmap against all glyph templates using Jaccard similarity
    (intersection / union). Returns (best_char, score)."""
    best_score = -1
    best_char = "?"
    for ch, glyph in GLYPHS.items():
        intersection = len(bitmap & glyph)
        union = len(bitmap | glyph)
        score = intersection / union if union > 0 else 0
        if score > best_score:
            best_score = score
            best_char = ch
    return best_char, best_score


# ============================================================
# STEP 7: Decode all 36 characters
# ============================================================
decoded = []
for i, (sc, ec) in enumerate(char_bounds):
    bitmap = extract_bitmap(sc, ec)
    ch, score = match_glyph(bitmap)
    log.info(f"  Char {i:2d}: cols [{sc:3d}-{ec:3d})  w={ec-sc}  → '{ch}'  (score={score:.2f})")
    decoded.append(ch)

flag = "".join(decoded)
log.success(f"Flag: {flag}")

# Save
write("flag.txt", (flag + "\n").encode())
log.info("Saved to flag.txt")
