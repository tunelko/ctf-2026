# The Trilogy of Death — Chapter III — The Poisoned Apple

| Field       | Value                              |
|-------------|------------------------------------|
| Platform    | srdnlen CTF 2026 Quals             |
| Category    | forensics                          |
| Difficulty  | Hard                               |
| Points      | —                                  |
| Author      | DaveZero                           |

## Description

> "He is gone. His last machine still holds its breath." His last machine is here. Still running. Still breathing - barely. The Armourer is dead, but the truth of what he was building across three lifetimes is waiting. He left a final note:
>
> "One taste of the poisoned apple, and the victim's eyes will close forever, in the Sleeping Death."
>
> 500.000 keys to decrypt the attached bin file. One of them is special. If you understand which one (and why), you will be able to decrypt the file. Note that each decryption attempt will consume roughly 90 seconds on a single core.
>
> DaveZero's note: This is NOT a crypto challenge NOR a stego challenge. It requires A LOT of technical knowledge to be solved (unless you manage to find an unintended solution).

## TL;DR

One key file (`key_449231.txt`) was overwritten after creation via APFS Copy-on-Write. The **original** key content survives as an orphaned data block in the raw image. Identifying the orphan by set-difference (raw image blocks vs. live filesystem contents) yields the correct decryption key.

## Initial Analysis

### Provided Files

| File                 | Size   | Description                            |
|----------------------|--------|----------------------------------------|
| `poisoned_apple.dmg` | 3.2 GB | GPT disk image (EFI + APFS partition)  |
| `encrypted_flag.bin` | 88 B   | Encrypted flag with PBKDF2 protection  |
| `decrypt_flag.py`    | 3.1 KB | Provided decryption script             |

### APFS Partition Extraction

```
$ file poisoned_apple.dmg
poisoned_apple.dmg: DOS/MBR boot sector; partition 1 : ... GUID Partition Table

$ python3 -c "
import pyfsapfs
c = pyfsapfs.container()
c.open('apfs_partition.raw')
v = c.get_volume(0)
print(f'Volume: {v.name}')
print(f'Volumes: {c.number_of_volumes}')
"
Volume: PoisonedApple
Volumes: 1
```

The DMG image contains a GPT table with a ~2.8 GB APFS partition. The volume is named **PoisonedApple**.

### Filesystem Structure

```
/
├── .fseventsd/          (186 FSEvents logs)
├── keys/                (500,000 key files: key_000000.txt ... key_499999.txt)
└── encrypted_flag.bin   (88 bytes)
```

Each `key_XXXXXX.txt` contains exactly 65 bytes: a 64-character hex string (32 bytes in binary) followed by a newline.

### encrypted_flag.bin

```
Salt:       653f2441ad29eb61f50d9b5176cfaa3f
Iterations: 140,000,000 (PBKDF2-SHA256)
Flag len:   32 bytes
Ciphertext: 592bbf79dc342e8370c5af6834949dd8bf6af07c16c27c35ce8a28325e07b04b
HMAC tag:   16550ef4aa2e3de4d3136fbe09f6a1e613427110756020b5e60d08aeb24ce69f
```

With 140M PBKDF2 iterations, each decryption attempt takes **~60-90 seconds**. Brute-forcing 500K keys is infeasible (~1 year on a single core).

## Vulnerability Identified

### Type: APFS Copy-on-Write (CoW) data leakage

APFS is a Copy-on-Write filesystem. When a file is modified, the original data block **is not overwritten**; instead, a new block is allocated with the new content and the B-tree is updated to point to the new block. The original block becomes an "orphan" — its content persists on disk even though it is no longer accessible through the filesystem.

## Solution Process

### Step 1: Identify the anomalous file via timestamps

Using `pyfsapfs` to inspect key file metadata, we found that **`key_449231.txt`** has unique timestamps:

```
Field                key_449231 (anomalous)           key_000001 (normal)
──────────────────── ──────────────────────────────── ────────────────────────────────
creation_time        2026-02-06 17:46:37.200105       2026-02-06 17:41:30.446384    <<<
modification_time    2026-02-06 17:45:40.436298       2026-02-06 17:41:30.446312
access_time          2026-02-06 17:48:30.993374       2026-02-06 17:41:30.446312    <<<
inode_change_time    2026-02-06 17:46:37.200105       2026-02-06 17:41:30.446384
```

The anomalies:

1. **creation_time = 17:46:37** — ~22 seconds after the last key file was created (key_499999 at 17:46:15). The file was **recreated/replaced** after the batch.
2. **modification_time = 17:45:40** — matches the original batch creation time (key_449230 was created at 17:45:40), indicating that the `mtime` was preserved from the previous version.
3. **access_time = 17:48:30** — 2 minutes after the last write operation. This file was **read** afterwards (likely to generate `encrypted_flag.bin` or to verify the encryption).

The neighbors (`key_449230`, `key_449232`) have normal identical creation/modification/access timestamps.

### Step 2: Confirm CoW via physical blocks

The data blocks of key_449231's neighbors are in a contiguous range:

```
key_449228: block 520741
key_449229: block 520742
key_449230: block 520650
key_449231: block 552732    ← VERY FAR from the rest
key_449232: block 520643
key_449233: block 520644
```

Block 552732 is ~32,000 blocks outside the expected range (~520640). This confirms that the content of `key_449231.txt` was **rewritten** to a new block (552732) while the original block was freed.

### Step 3: Detect the FSEvents log of the modification

The log `.fseventsd/0000000000a3aae3` (the second most recent) records:

```
_dummy_cow_0.txt  ... _dummy_cow_4.txt    (5 dummy CoW files)
_dummy_post_0.txt ... _dummy_post_2.txt   (3 dummy post files)
keys/key_449231.txt                        (the modified key)
keys/key_499587.txt ... key_499999.txt     (the last keys of the batch)
```

The `_dummy_cow_X.txt` and `_dummy_post_X.txt` files were created and then deleted — likely to force additional CoW operations and make analysis harder.

### Step 4: Scan raw blocks for hex keys

We scanned the entire raw image (3 GB, 735,222 blocks of 4096 bytes) looking for blocks that begin with exactly 64 hex characters followed by a newline:

```python
for blk in range(total_blocks):
    chunk = raw[blk * 4096 : blk * 4096 + 65]
    if re.match(rb"^[0-9a-f]{64}\n?$", chunk.rstrip(b"\x00")):
        aligned_keys[chunk[:64].decode()].append(blk)
```

**Result: 500,001 unique hex keys in aligned blocks.**

500,000 correspond to the current files. The **501st** is the CoW orphan — the original content of `key_449231.txt`.

### Step 5: Set-difference to find the orphan

We read the contents of all 500,000 `key_XXXXXX.txt` files via `pyfsapfs`:

```python
for num in range(500_000):
    entry = vol.get_file_entry_by_path(f"/keys/key_{num:06d}.txt")
    entry.seek_offset(0, 0)
    fs_keys.add(entry.read_buffer(entry.size).strip().decode())
```

Then we compute:

```python
orphans = aligned_keys - fs_keys
```

**Result: 2 orphans** (one due to a read error on `key_208478`, a `pyfsapfs` quirk):

```
39f520679fd68654500f9cd44e8caed2bc897a3227dc297c4520336de2a59dd7  ← block 520651
3f42e507315cb367fb8e048173e9c18c1276510f677d3655502ca94ee9327823  ← block 520647 (key_208478, read error)
```

### Step 6: Decrypt the flag

```bash
$ python3 decrypt_flag.py encrypted_flag.bin \
    39f520679fd68654500f9cd44e8caed2bc897a3227dc297c4520336de2a59dd7

[*] Salt: 653f2441ad29eb61f50d9b5176cfaa3f
[*] PBKDF2 iterations: 140,000,000
[*] Flag length: 32
[*] Key derivation took 58.2s

[✓] SUCCESS! Decrypted flag:
    srdnlen{b3h0ld_th3_d34dl1_APFS!}
```

## Discarded Approaches

| Approach | Result | Why it failed |
|----------|--------|---------------|
| Try the current key from `key_449231.txt` (`b1a64c6e...`) | WRONG KEY | It is the REPLACEMENT content, not the original |
| 13 "regex-only-orphan" keys (boundary match issue) | WRONG KEY x 13 | They were keys from current files that the regex missed due to lookbehind boundary issues |
| Keys from APFS B-tree root hashes | WRONG KEY x 6 | Filesystem metadata, not file contents |
| Keys from historical extent records (blocks 455958, 481916) | WRONG KEY | They belonged to other files or B-tree nodes, not the original content |
| Content of dummy_cow/dummy_post files | Not accessible | Files deleted from the filesystem, `pyfsapfs` returns None |
| Mount APFS with FUSE (`fsapfsmount`) | Failed | Binary not compiled with FUSE support |
| Parse APFS allocation bitmap | 0 free blocks with keys | Orphan blocks are still marked as allocated |

## Final Exploit

`solve.py` — Complete solver in 4 phases:

1. **Identify**: Detects `key_449231.txt` via timestamp anomalies
2. **Scan**: Scans raw blocks for aligned hex keys (500,001)
3. **Read**: Reads all 500,000 keys from the filesystem via `pyfsapfs`
4. **Diff + Decrypt**: Set-difference -> orphan -> PBKDF2 -> flag

## Execution

```bash
cd /home/student/ctfs/srdnlen2026/misc/trilogy3/
python3 solve.py
```

Total time: ~5 minutes (4 min reading 500K keys + 1 min PBKDF2).

## Flag

```
srdnlen{b3h0ld_th3_d34dl1_APFS!}
```

## Attack Timeline

```
17:41:28  encrypted_flag.bin created (with the ORIGINAL key from key_449231)
17:41:30  Batch start: key_000000.txt ...
17:45:40  key_449231.txt created (original content: 39f52067...)  ← THE KEY
17:46:15  Batch end: key_499999.txt
17:46:37  key_449231.txt OVERWRITTEN via CoW (new content: b1a64c6e...)
17:46:37  dummy_cow_0..4.txt and dummy_post_0..2.txt created and deleted
17:48:30  key_449231.txt accessed (verification read)
```

## Key Lessons

- **APFS CoW preserves original data**: When a file is modified, the original data block persists on disk as an "orphan block" until the space is reclaimed by the filesystem.
- **APFS timestamps are granular**: `creation_time`, `modification_time`, `access_time`, and `inode_change_time` are stored independently with nanosecond resolution. Discrepancies between them reveal post-creation operations.
- **Set-difference raw vs. filesystem**: Comparing all data blocks in the raw image against the live filesystem contents is a powerful method for detecting CoW artifacts, residual snapshots, or deleted files whose content persists.
- **PBKDF2 as anti-brute-force mechanism**: 140M iterations (~60s/attempt) makes brute force impractical, forcing precise forensic analysis to identify the correct key.
- **The dummy files were red herrings**: The `_dummy_cow_X.txt` and `_dummy_post_X.txt` files were created and deleted to generate noise in the CoW history and make APFS transaction analysis harder.

## References

- [APFS Reference - Apple Developer](https://developer.apple.com/support/downloads/Apple-File-System-Reference.pdf) — Official format specification
- [libfsapfs - Joachim Metz](https://github.com/libyal/libfsapfs) — APFS access library used via python3-fsapfs
- [APFS Internals - Kurt Hansen (DFRWS)](https://www.sciencedirect.com/science/article/pii/S1742287619301252) — Forensic analysis of APFS CoW artifacts
