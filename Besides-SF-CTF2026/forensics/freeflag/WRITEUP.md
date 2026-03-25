# freeflag — BSidesSF CTF 2026

| Field | Value |
|-------|-------|
| **Category** | Forensics |
| **Points** | 785 |
| **Author** | symmetric |
| **Flag** | `CTF{flag_of_the_free}` |

## Description

> Here, have a ton of flags. Oh? You're looking for THAT flag? It isn't a file.

## TL;DR

FAT16 filesystem image containing ~250 country flag PNGs. The CTF flag is in a deleted PNG image whose data remains in unallocated (free) clusters.

## Analysis

```
$ file freeflag.bin
DOS/MBR boot sector, OEM-ID "freeflag", label: "FREESPACE", FAT (16 bit)
```

16MB FAT16 image. Mounting it reveals ~250 PNG files named by ISO country codes (`ad.png`, `ae.png`, etc.) — literal country flags.

The hint "it isn't a file" means the flag isn't in any of the existing files. Key observation: **cluster 2** (the first data cluster) is marked as FREE in the FAT table but contains a valid PNG header (`89504e47`).

## Solution

### Parse FAT and find free clusters with data

```python
for i in range(2, total_clusters + 2):
    entry = struct.unpack_from('<H', fat, i * 2)[0]
    if entry == 0x0000:  # Free cluster
        cluster_data = data[data_start + (i-2) * cluster_size : ...]
        if any(b != 0 for b in cluster_data):
            free_data.extend(cluster_data)
```

Result: **794 non-empty free clusters** containing **1.6MB** of data starting with a PNG header.

### Reconstruct the deleted image

The free clusters are sequential (2, 2598-3391), so concatenating their data produces a valid PNG:

```python
with open("free_image.png", "wb") as f:
    f.write(bytes(free_data[:iend_pos + 8]))
# → 1536x1024 PNG with the flag
```

The recovered image shows `CTF{flag_of_the_free}`.

## Key Takeaways

- **Deleted files leave data behind** — FAT deletion only marks clusters as free and overwrites the first byte of the directory entry with `0xE5`. The actual file data persists until overwritten.
- **"It isn't a file"** — the PNG exists as raw data in unallocated space, not as a file entry in the directory. Standard `ls`/`mount` won't show it.
- **Volume label "FREESPACE"** was the hint — look in the free space.

## Files

- `freeflag.bin` — FAT16 filesystem image (16MB)
- `free_image.png` — recovered flag image from free clusters
- `flag.txt` — `CTF{flag_of_the_free}`
