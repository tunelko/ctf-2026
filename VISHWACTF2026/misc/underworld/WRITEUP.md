# UnderWorld - P1 & P2

**CTF**: VishwaCTF 2026
**Category**: Misc
**Author**: phoenixx

## Part 1

**Flag**: `VishwaCTF{m1n3cr4f7_15_fun}`

### TL;DR

Minecraft world save file. Flag hidden as custom-named diamonds in a chest — each diamond named with one character, ordered by inventory slot.

### Analysis

The handout is a Minecraft 1.21.11 world (Fabric server) with a superflat terrain: bedrock → emerald_block → lava layers.

Standard tools (`anvil-parser`, `nbtlib`) couldn't find the flag via block scanning because the chests exist as **block entities** in the NBT data, not as visible blocks in the palette.

### Solution

Parse region files at the raw NBT level to find block entities:

```python
# Read region/r.0.-1.mca, find block entities with Items
# Each item is a diamond with a custom_name of one character
# Sorted by Slot number, they spell the flag
```

**Chest 1** (decoy) at (86, 13, -z): Diamonds spelling `"No Emeralds here"`

**Chest 2** (flag) at another location: Diamonds spelling `"VishwaCTF{m1n3cr4f7_15_fun}"`

Each diamond occupies one slot (0-26), and the `minecraft:custom_name` component contains a single character.

---

## Part 2

**Flag**: `VishwaCTF{5w33t_gr33n_3m3r4ld}`

### TL;DR

Emerald blocks placed in the lava layer at y=-60 form pixel-art text when viewed from above. Snap coordinates to a 26-block grid and read bottom-to-top.

### Analysis

The challenge says "Emerald blocks are the most precious blocks." The superflat world has an emerald_block layer, but at y=-60 (inside the lava layer), **454 individual emerald blocks** were placed in specific positions.

### Solution

#### Step 1: Find the emerald blocks

Scan all region files at y=-60 for blocks that differ from the expected lava:

```python
# Section Y=-4 contains the lava/emerald transition
# At y=-60, 454 blocks are emerald instead of lava
```

#### Step 2: Determine the grid

The blocks are spaced ~26 blocks apart, forming a regular grid. Each block represents one pixel of pixel-art text.

```python
grid_size = 26
gx = round((x - offset) / grid_size)
gz = round((z - offset) / grid_size)
```

#### Step 3: Render and read

The grid produces a 39x58 pixel image. Reading bottom-to-top (Minecraft Z-axis, as text was built upward):

```
Line 6 (bottom): Vishwa
Line 5:          CTF{5
Line 4:          w33t_
Line 3:          gr33n
Line 2:          _3m3r
Line 1 (top):    4ld}
```

Combined: `VishwaCTF{5w33t_gr33n_3m3r4ld}` ("sweet green emerald")

## Key Takeaways

- Minecraft worlds are rich forensic targets — data hides in block entities (chests, signs), entity NBT, and block placement patterns
- Block entity data (chests with named items) doesn't appear in block palette scans — must parse raw chunk NBT
- Large-scale pixel art in Minecraft uses the X-Z plane viewed from above; the grid spacing must be detected to read the text
- Player stats (`open_chest: 3`) can hint at what to look for

## Files

- `handout_Oczmx6J.zip` — Challenge archive
- `UnderWorld/` — Minecraft world save
- `flag.txt` — P1 flag
- `flag_p2.txt` — P2 flag
- `grid_text.png` — Rendered emerald block pixel art
