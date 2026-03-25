# orphan — BSidesSF 2026 (Forensics, 101pts)

## TL;DR

XZ-compressed ext2 filesystem image. The flag is in an orphaned inode (linked but not in any directory entry). Dump inode 13 with `debugfs` to recover a PNG containing the flag.

## Flag

```
CTF{please_sir_can_i_have_a_flag}
```

## Description

We're given a single file `orphan.bin`. The challenge title and description hint at something "orphaned" in a filesystem.

## Analysis

```bash
$ file orphan.bin
orphan.bin: XZ compressed data

$ xz -d orphan.bin --stdout > orphan_decomp
$ file orphan_decomp
orphan_decomp: Linux rev 1.0 ext2 filesystem data
```

### Filesystem contents

```bash
$ debugfs orphan_decomp -R 'ls -l /'
  2  40755 (2)   0   0    1024 21-Mar-2026 19:59 .
  2  40755 (2)   0   0    1024 21-Mar-2026 19:59 ..
 11  40700 (2)   0   0   12288 21-Mar-2026 19:58 lost+found
 12 100644 (1)   0   0 1627811 21-Mar-2026 19:59 where.gif
```

Only `where.gif` (a confused Travolta meme — a red herring) and an empty `lost+found`.

### Hunting the orphan

```bash
$ debugfs orphan_decomp -R 'lsdel'
```

This reveals inode 14 was deleted (zeroed data blocks — unrecoverable).

Enumerating all inodes reveals **inode 13**: `links=1`, `size=2573106`, `Type: regular` — allocated and holding data, but **not referenced by any directory entry**. This is the orphaned inode.

## Vulnerability / Technique

An **orphan inode** is allocated in the inode table with valid data blocks and a non-zero link count, but no directory entry points to it. Standard tools (`ls`, `find`, mounting the filesystem) will never show it. Only low-level filesystem tools like `debugfs` can access it by inode number.

## Exploit / Recovery

```bash
debugfs orphan_decomp -R 'dump <13> orphan_flag.png'
```

This extracts a PNG image (1024x627) — an Oliver Twist still from the 1948 film with the flag text at the bottom.

## Approaches Discarded

- Mounting the filesystem and searching normally — the file has no directory entry
- Recovering deleted inode 14 — data blocks were zeroed

## Key Lessons

- Challenge name is always a hint: "orphan" → orphan inode
- `debugfs` is essential for ext2/3/4 forensics — enumerate all inodes, not just directory listings
- `lsdel` finds deleted inodes, but manually scanning the inode table finds orphaned (non-deleted but unreferenced) ones
