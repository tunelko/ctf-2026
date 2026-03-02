# Space USB - Forensics Writeup

**Category:** Forensics
**Event:** UniVsThreats 2026 Quals
**Flag:** `UVT{d0nt_k33p_d1GG1in_U_sur3ly_w0Nt_F1nD_aNythng_:)}`

## Challenge Description

> While we were scouring through space in our spaceship, conquering through the stars and planets, our team found A LONE USB STICK! FLOATING THROUGH SPACE INTACT!!! Find out what happened here and retrieve the useful information.

**Provided:** `space_usb.img` (128 MiB disk image)

---

## Step 1 — Disk Image Reconnaissance

```bash
$ file space_usb.img
DOS/MBR boot sector; partition 1 : ID=0xee, startsector 1, 262143 sectors

$ fdisk -l space_usb.img
Disklabel type: gpt
Device     Start    End Sectors Size Type
...img1     8192 204799  196608  96M Microsoft basic data
...img2   204800 253951   49152  24M Linux filesystem
```

Two partitions:
- **Partition 1** — FAT32, 96 MiB (offset `8192 × 512 = 4194304`)
- **Partition 2** — ext4, 24 MiB (offset `204800 × 512 = 104857600`)

Mount both:

```bash
mount -o loop,offset=4194304,ro space_usb.img /tmp/usb_p1
losetup --find --show --offset 104857600 --sizelimit 25165824 space_usb.img
# → /dev/loop1
mount -o ro /dev/loop1 /tmp/usb_p2
```

---

## Step 2 — Partition 1 (FAT32): Active Files

```
/tmp/usb_p1/
├── readme.txt          (1297 bytes)
├── logs/crew_log.txt   (1374 bytes)
├── bin/airlockauth     (14472 bytes, ELF 64-bit stripped)
├── nav.bc              (256 bytes)
└── payload.enc         (40 bytes)
```

### readme.txt (key excerpts)

> This device contains navigation telemetry, crew logs, and the station authentication console. [...] The binary reads nav.bc, payload.enc, and seed32.bin from the current working directory. If your token is valid, you will see: "signal verified"

> **NOTE:** The diagnostic cache partition may contain leftover telemetry data from previous maintenance cycles. This data is scheduled for periodic purge and should not be relied upon.

### crew_log.txt (key excerpts)

```
[11:03] === CREW AUTH NOTE ===
        Crew authentication prefix for this rotation: ASTRA9-
        Reminder: DO NOT store full access token in plaintext logs.
        Second half of token rotated per-cycle, stored in secure cache.

[14:55] Encrypted telemetry fragments (alpha/bravo/charlie) moved to
        diagnostics cache along with the XOR key per SOP-7.
        NOTE: debrief file in same cache explains reassembly.

[15:45] Cache partition scheduled for purge per standard ops.
        All files in /diagnostics and /tmp marked for deletion.
```

**Key clues:**
1. Token prefix is `ASTRA9-`, second half is in the "secure cache" (partition 2)
2. Telemetry fragments alpha/bravo/charlie + XOR key were moved to diagnostics cache
3. Cache was **purged** (files deleted) — we need to recover them

---

## Step 3 — Partition 2 (ext4): Deleted File Recovery

The ext4 partition's directories are empty — all files were deleted. Use `debugfs` to find and recover them:

```bash
$ debugfs -R "lsdel" /dev/loop1

 Inode  Owner  Mode    Size    Blocks  Time deleted
    17      0 100755     32      1/1   Thu Feb 26 20:05:26 2026
    18      0 100755      9      1/1   Thu Feb 26 20:05:26 2026
    19      0 100755    663      1/1   Thu Feb 26 20:05:26 2026
    20      0 100755     16      1/1   Thu Feb 26 20:05:26 2026
    21      0 100755     66      1/1   Thu Feb 26 20:05:26 2026
    22      0 100755     84      1/1   Thu Feb 26 20:05:26 2026
    23      0 100755     70      1/1   Thu Feb 26 20:05:26 2026
    24-31   ...         (more TLM fragments: delta-kilo)
    32-37   ...         (larger data blobs)
21 deleted inodes found.
```

Recover each inode:

```bash
for i in $(seq 17 37); do
  debugfs -R "dump <$i> /tmp/recovered/inode_$i" /dev/loop1
done
```

### Recovered Files Identification

| Inode | Size | Identified As | Content |
|-------|------|---------------|---------|
| 17 | 32 B | `seed32.bin` | `aa882a927ccab9a8...` (32-byte binary seed) |
| 18 | 9 B | `crew_id.part2` | `BRO-1337\n` (second half of auth token) |
| 19 | 663 B | `mission_debrief.txt` | Reassembly instructions (see below) |
| 20 | 16 B | `diag_key.bin` | `ccb54a5245335776759eb342afd779db` (XOR key) |
| 21 | 66 B | `telemetry_alpha.bin` | TLM fragment, seq=1 |
| 22 | 84 B | `telemetry_bravo.bin` | TLM fragment, seq=2 |
| 23 | 70 B | `telemetry_charlie.bin` | TLM fragment, seq=3 |
| 24-31 | varies | `telemetry_delta-kilo` | TLM fragments, seq=4-11 (noise) |
| 32-37 | 2-3 KB | misc data blobs | nav_ephemeris, comms_buffer, etc. |

### mission_debrief.txt (inode 19)

```
=== ASTRA-9 MISSION DEBRIEF -- CLASSIFIED ===

NOTICE:
  Diagnostic verification token was encrypted per SOP-7 and split
  across telemetry fragments alpha/bravo/charlie in this cache.
  XOR key stored in companion file diag_key.bin.
  Fragment format: TLM header (7 bytes) + padding + encrypted data.
  Reassemble in sequence order (field at offset 4) after decryption.
```

This tells us exactly what to do: decrypt fragments alpha/bravo/charlie with the XOR key and reassemble in order.

---

## Step 4 — Red Herring: The airlockauth Binary

Before finding the real flag, there's an obvious rabbit hole: the `airlockauth` binary.

### Token Construction

From the crew log prefix `ASTRA9-` + recovered `crew_id.part2` = `BRO-1337`:

```bash
$ echo "ASTRA9-BRO-1337" | ./airlockauth
signal verified
```

### Binary Reverse Engineering (r2/objdump)

The binary's algorithm (reversed from assembly at `0x1300-0x15b2`):

```
1. Read seed32.bin, nav.bc, payload.enc
2. Read token from stdin
3. nav_hash = SHA256(nav.bc)
4. combined = seed32 || token || nav_hash    (32 + 15 + 32 = 79 bytes)
5. key = SHA256(combined)
6. decrypted[i] = payload.enc[i] ^ key[i % 32]
7. Check if decrypted starts with "UVT{" (cmp dword 0x7b545655)
8. Print "signal verified" or "access denied"
```

This decryption produces: `UVT{S0m3_s3cR3tZ_4r_nVr_m3Ant_t0_B_SHRD}`

**This is a DECOY FLAG.** It looks valid but does not pass validation. The binary only prints "signal verified"/"access denied" and never outputs the decrypted payload — the result is a trap for anyone who reverses the binary without reading the other clues.

---

## Step 5 — TLM Fragment Decryption (The Real Flag)

### Fragment Format

Each TLM fragment has this structure:

```
Offset  Size  Field
0       3     Magic ("TLM")
3       1     Version (0x01)
4       1     Sequence number (1-11)
5       1     Plaintext message length
6       1     Reserved (0x00)
7+      var   Random padding + XOR-encrypted message bytes
```

Hex dump of the three relevant fragments:

```
alpha (inode 21, 66 bytes, seq=1, msg_len=17):
  544c4d01 011100 d094aea54013cf3ecb801663cfac8b2192
  acab5182f3fa1ab01ab199e31e2921033902 2af58071df88
  1dea8b3f09cb87250917b2429a72044fcfeb

bravo (inode 22, 84 bytes, seq=2, msg_len=17):
  544c4d01 021100 c5aebc94f7141221fd44db7b75cb6df9dc
  eda5d0de6448c2b8b3e3722b67931099...

charlie (inode 23, 70 bytes, seq=3, msg_len=18):
  544c4d01 031200 d96ddbfb2bfafa41533c224362520f0bb8
  ea0c632b7708173be7c72ac1b026e1e5...
```

### Decryption Method

The encrypted message bytes are embedded at a **variable offset** within the random padding that follows the 7-byte header. Byte 5 tells us the message length. The XOR key (`diag_key.bin`, 16 bytes) is applied starting at key offset 0.

To find the message position, we brute-force the start offset within each fragment: try every possible position and check which one decrypts to **all printable ASCII**:

```python
xor_key = open("diag_key.bin", "rb").read()  # 16 bytes

for start in range(7, len(fragment) - msg_len + 1):
    encrypted = fragment[start : start + msg_len]
    decrypted = bytes(encrypted[i] ^ xor_key[i % 16] for i in range(msg_len))
    if all(32 <= b < 127 for b in decrypted):
        print(f"Found at offset {start}: {decrypted.decode()}")
```

### Results

| Fragment | Seq | Msg Len | Data Offset | Decrypted |
|----------|-----|---------|-------------|-----------|
| alpha | 1 | 17 | 34 | `UVT{d0nt_k33p_d1G` |
| bravo | 2 | 17 | 45 | `G1in_U_sur3ly_w0N` |
| charlie | 3 | 18 | 23 | `t_F1nD_aNythng_:)}` |

### Reassembly

Concatenating in sequence order (1 → 2 → 3):

```
UVT{d0nt_k33p_d1G + G1in_U_sur3ly_w0N + t_F1nD_aNythng_:)}
```

**Flag: `UVT{d0nt_k33p_d1GG1in_U_sur3ly_w0Nt_F1nD_aNythng_:)}`**

> "don't keep digging, you surely won't find anything :)"

---

## Solution Summary

```
space_usb.img
├── Partition 1 (FAT32)
│   ├── readme.txt ──────────── hints at diagnostic cache & binary usage
│   ├── crew_log.txt ────────── token prefix "ASTRA9-", points to fragments
│   ├── bin/airlockauth ─────── RED HERRING (decoy flag)
│   ├── nav.bc
│   └── payload.enc
│
└── Partition 2 (ext4, all files DELETED)
    ├── seed32.bin ──────────── needed for binary (decoy path)
    ├── crew_id.part2 ───────── "BRO-1337" (token suffix)
    ├── mission_debrief.txt ──► KEY: "decrypt alpha/bravo/charlie with XOR key"
    ├── diag_key.bin ─────────► 16-byte XOR key
    ├── telemetry_alpha ──────► fragment 1: "UVT{d0nt_k33p_d1G"
    ├── telemetry_bravo ──────► fragment 2: "G1in_U_sur3ly_w0N"
    └── telemetry_charlie ────► fragment 3: "t_F1nD_aNythng_:)}"
```

---

## Scripts

- `solve.py` — Full automated solution: recovers deleted files from ext4, decrypts TLM fragments, assembles flag

---

## Key Lessons

1. **Read ALL the clues before going deep.** The crew_log and mission_debrief explicitly pointed to the telemetry fragments. Jumping straight into binary RE leads to the decoy flag.
2. **Deleted files are never truly gone on ext4.** `debugfs lsdel` + `dump <inode>` recovers everything unless blocks are overwritten.
3. **Watch for red herrings in CTF.** The airlockauth binary was a fully functional decoy — it produced a valid-looking `UVT{...}` flag designed to waste time.
4. **TLM fragment structure** used variable-offset message embedding within random padding, requiring brute-force position-finding rather than a fixed offset.
5. **The flag itself is a troll:** "don't keep digging, you surely won't find anything :)" — a message to those who already found it by digging through deleted files.
