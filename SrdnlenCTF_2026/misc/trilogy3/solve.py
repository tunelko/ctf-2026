#!/usr/bin/env python3
"""
The Trilogy of Death - Chapter III - The Poisoned Apple
Category: forensics
Platform: srdnlen CTF 2026 Quals

Solver: Identifies the special key among 500,000 by detecting APFS
Copy-on-Write orphan blocks, then decrypts the flag.

Requires: pyfsapfs (python3-fsapfs), ~4 min to read all 500K key files.
"""
import re
import struct
import sys
import pyfsapfs

IMAGE = "apfs_partition.raw"
ENCRYPTED = "encrypted_flag.bin"


def collect_aligned_keys(raw: bytes, block_size: int = 4096) -> dict[str, list[int]]:
    """Find all 64-char hex strings at block-aligned offsets (key file data blocks)."""
    keys: dict[str, list[int]] = {}
    total_blocks = len(raw) // block_size
    for blk in range(total_blocks):
        off = blk * block_size
        chunk = raw[off : off + 65]
        if re.match(rb"^[0-9a-f]{64}\n?$", chunk.rstrip(b"\x00")):
            k = chunk[:64].decode()
            keys.setdefault(k, []).append(blk)
    return keys


def collect_filesystem_keys(image_path: str) -> set[str]:
    """Read all 500K key file contents from the live APFS filesystem."""
    container = pyfsapfs.container()
    container.open(image_path)
    vol = container.get_volume(0)

    fs_keys: set[str] = set()
    errors = []
    for num in range(500_000):
        if num % 50_000 == 0:
            print(f"  Reading key_{num:06d}... ({len(fs_keys)} collected)")
        path = f"/keys/key_{num:06d}.txt"
        try:
            entry = vol.get_file_entry_by_path(path)
            entry.seek_offset(0, 0)
            content = entry.read_buffer(entry.size).strip().decode()
            fs_keys.add(content)
        except Exception as e:
            errors.append((num, str(e)))

    if errors:
        print(f"  [!] {len(errors)} read errors (pyfsapfs quirk)")
    return fs_keys


def identify_anomalous_file(image_path: str) -> None:
    """Show timestamp anomaly on key_449231.txt for forensic justification."""
    container = pyfsapfs.container()
    container.open(image_path)
    vol = container.get_volume(0)

    target = vol.get_file_entry_by_path("/keys/key_449231.txt")
    normal = vol.get_file_entry_by_path("/keys/key_000001.txt")

    print("[*] Timestamp comparison (forensic evidence):\n")
    print(f"  {'Field':<20s} {'key_449231 (anomalous)':<32s} {'key_000001 (normal)'}")
    print(f"  {'─'*20} {'─'*32} {'─'*32}")
    for field in ["creation_time", "modification_time", "access_time", "inode_change_time"]:
        tv = str(getattr(target, field))
        nv = str(getattr(normal, field))
        marker = " <<<" if tv != nv and field in ("creation_time", "access_time") else ""
        print(f"  {field:<20s} {tv:<32s} {nv}{marker}")

    target.seek_offset(0, 0)
    current_key = target.read_buffer(target.size).strip().decode()
    print(f"\n  Current content: {current_key}")
    print(f"  (This is the REPLACEMENT key written via CoW, NOT the original)")


def main():
    print("=" * 72)
    print(" The Trilogy of Death - Chapter III - The Poisoned Apple")
    print(" APFS Copy-on-Write Forensics Solver")
    print("=" * 72)

    # --- Step 1: Identify the anomalous file ---
    print("\n[1/4] Identifying anomalous key file via timestamps...")
    identify_anomalous_file(IMAGE)

    # --- Step 2: Scan raw image for block-aligned hex keys ---
    print("\n[2/4] Scanning raw image for block-aligned hex keys...")
    with open(IMAGE, "rb") as f:
        raw = f.read()
    aligned = collect_aligned_keys(raw)
    print(f"  Found {len(aligned)} unique block-aligned hex keys")

    # --- Step 3: Read all 500K keys from live filesystem ---
    print("\n[3/4] Reading all 500,000 key files from APFS filesystem...")
    fs_keys = collect_filesystem_keys(IMAGE)
    print(f"  Collected {len(fs_keys)} unique filesystem keys")

    # --- Step 4: Find orphan CoW keys ---
    print("\n[4/4] Computing set difference (aligned - filesystem)...")
    orphans = set(aligned.keys()) - fs_keys
    print(f"  Orphan keys found: {len(orphans)}")
    for key in sorted(orphans):
        blocks = aligned[key]
        print(f"    {key}  (block{'s' if len(blocks)>1 else ''} {blocks})")

    # --- Decrypt ---
    if orphans:
        print(f"\n[*] Testing {len(orphans)} orphan key(s) against encrypted_flag.bin...")
        print(f"    Each attempt takes ~60-90 seconds (PBKDF2 with 140M iterations)")
        print()
        for key in sorted(orphans):
            print(f"  Trying: {key}")
            # Inline decryption to avoid subprocess overhead
            import hashlib, hmac as hmac_mod
            with open(ENCRYPTED, "rb") as f:
                enc_data = f.read()
            salt = enc_data[0:16]
            iterations, flag_len = struct.unpack_from("<II", enc_data, 16)
            padded_len = ((flag_len + 31) // 32) * 32
            ciphertext = enc_data[24 : 24 + padded_len]
            stored_tag = enc_data[24 + padded_len : 24 + padded_len + 32]

            key_bytes = bytes.fromhex(key)
            import time
            t0 = time.time()
            derived = hashlib.pbkdf2_hmac("sha256", key_bytes, salt, iterations)
            elapsed = time.time() - t0
            print(f"    PBKDF2 took {elapsed:.1f}s")

            computed_tag = hmac_mod.new(derived, ciphertext, hashlib.sha256).digest()
            if hmac_mod.compare_digest(computed_tag, stored_tag):
                plaintext = bytearray()
                for i in range(0, len(ciphertext), 32):
                    block_key = hashlib.sha256(
                        derived + struct.pack("<I", i // 32)
                    ).digest()
                    for j in range(min(32, len(ciphertext) - i)):
                        plaintext.append(ciphertext[i + j] ^ block_key[j])
                flag = bytes(plaintext[:flag_len]).decode("utf-8", errors="replace")
                print(f"\n  [+] SUCCESS! Flag: {flag}")
                return
            else:
                print(f"    WRONG KEY (HMAC mismatch)")

    print("\n[-] No valid key found among orphans.")
    sys.exit(1)


if __name__ == "__main__":
    main()
