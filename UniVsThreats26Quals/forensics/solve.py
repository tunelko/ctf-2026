#!/usr/bin/env python3
"""
Space USB - Forensics Challenge Solver
UniVsThreats 2026 Quals

The flag is split across 3 deleted TLM telemetry fragments (alpha/bravo/charlie)
on the ext4 partition of a USB disk image. Each fragment is XOR-encrypted with
a 16-byte key (diag_key.bin), also deleted.

Steps:
  1. Mount ext4 partition from the GPT disk image
  2. Recover deleted inodes via debugfs (17-31)
  3. Extract XOR key from inode 20 (diag_key.bin)
  4. Decrypt TLM fragments alpha(21), bravo(22), charlie(23)
  5. Reassemble flag in sequence order

Usage:
  python3 solve.py              # from directory containing space_usb.img
  python3 solve.py --recovered  # from directory with pre-extracted inode files
"""
import subprocess
import os
import sys
import tempfile

IMG = "space_usb.img"

# Partition 2 (ext4) starts at sector 204800
P2_SECTOR_START = 204800
P2_OFFSET = P2_SECTOR_START * 512  # 104857600
P2_SECTORS = 49152
P2_SIZE = P2_SECTORS * 512  # 25165824


def run(cmd):
    """Execute shell command, return result."""
    return subprocess.run(cmd, shell=True, capture_output=True, text=False)


def recover_deleted_inodes(img_path):
    """
    Recover deleted files from the ext4 partition using debugfs.
    Returns dict of {inode_number: bytes}.
    """
    tmpdir = tempfile.mkdtemp(prefix="usb_forensics_")
    recovered = {}

    # Create a loop device pointing to the ext4 partition
    lo = run(f"losetup --find --show --offset {P2_OFFSET} --sizelimit {P2_SIZE} {img_path}")
    loop_dev = lo.stdout.decode().strip()

    if not loop_dev:
        print("[-] Failed to create loop device. Are you root?")
        sys.exit(1)

    print(f"[*] Loop device: {loop_dev}")

    # List deleted inodes
    lsdel = run(f'debugfs -R "lsdel" {loop_dev}')
    print(f"[*] Deleted inodes found:")
    for line in lsdel.stdout.decode().splitlines():
        if line.strip() and not line.startswith(" Inode"):
            parts = line.split()
            if parts:
                print(f"    inode {parts[0]:>3s}  size={parts[3]:>5s} bytes")

    # Dump each relevant inode (17-31 contain our target files)
    for inode in range(17, 32):
        out_path = os.path.join(tmpdir, f"inode_{inode}")
        run(f'debugfs -R "dump <{inode}> {out_path}" {loop_dev}')
        if os.path.exists(out_path) and os.path.getsize(out_path) > 0:
            with open(out_path, "rb") as f:
                recovered[inode] = f.read()

    # Clean up loop device
    run(f"losetup -d {loop_dev}")

    return recovered


def load_preextracted():
    """Load pre-extracted inode files from current directory or /tmp/recovered/."""
    recovered = {}
    search_dirs = [".", "/tmp/recovered"]

    for d in search_dirs:
        for inode in range(17, 32):
            path = os.path.join(d, f"inode_{inode}")
            if os.path.exists(path) and os.path.getsize(path) > 0:
                with open(path, "rb") as f:
                    recovered[inode] = f.read()

    return recovered


def decrypt_tlm_fragment(fragment_data, xor_key):
    """
    Decrypt a TLM telemetry fragment.

    Format:
      Bytes 0-2:  "TLM" magic
      Byte 3:     Version (0x01)
      Byte 4:     Sequence number
      Byte 5:     Plaintext message length
      Byte 6:     Reserved (0x00)
      Bytes 7+:   Random padding + XOR-encrypted message

    The message is embedded at a variable offset within the data after
    the 7-byte header. We brute-force the start position by trying
    all offsets and checking which produces all-printable ASCII output
    when XOR'd with the key (starting at key offset 0).
    """
    if len(fragment_data) < 7 or fragment_data[:3] != b"TLM":
        return None

    msg_len = fragment_data[5]
    total = len(fragment_data)

    for start in range(7, total - msg_len + 1):
        encrypted = fragment_data[start : start + msg_len]
        decrypted = bytearray(msg_len)
        for i in range(msg_len):
            decrypted[i] = encrypted[i] ^ xor_key[i % len(xor_key)]

        # All bytes must be printable ASCII
        if all(32 <= b < 127 for b in decrypted):
            return start, decrypted.decode("ascii")

    return None


def main():
    use_preextracted = "--recovered" in sys.argv

    # --- Step 1: Recover deleted files ---
    if use_preextracted:
        print("[*] Loading pre-extracted inode files...")
        recovered = load_preextracted()
    elif os.path.exists(IMG):
        print(f"[*] Processing disk image: {IMG}")
        recovered = recover_deleted_inodes(IMG)
    else:
        print(f"[-] Image '{IMG}' not found. Use --recovered for pre-extracted files.")
        sys.exit(1)

    if not recovered:
        print("[-] No recovered files found.")
        sys.exit(1)

    print(f"[*] Recovered {len(recovered)} inodes")

    # --- Step 2: Identify key files ---
    # inode 18 = crew_id.part2 (token suffix, for context)
    if 18 in recovered:
        crew_part2 = recovered[18].strip().decode("utf-8", errors="replace")
        print(f"[*] crew_id.part2: {crew_part2}")
        print(f"[*] Full auth token: ASTRA9-{crew_part2}")

    # inode 19 = mission_debrief.txt
    if 19 in recovered:
        debrief = recovered[19].decode("utf-8", errors="replace")
        print(f"[*] mission_debrief.txt recovered ({len(recovered[19])} bytes)")

    # inode 20 = diag_key.bin (16-byte XOR key)
    if 20 not in recovered:
        print("[-] diag_key.bin (inode 20) not found!")
        sys.exit(1)

    xor_key = recovered[20]
    print(f"[*] XOR key (diag_key.bin): {xor_key.hex()}")

    # --- Step 3: Parse TLM fragments ---
    fragments = {}
    frag_names = {1: "alpha", 2: "bravo", 3: "charlie", 4: "delta", 5: "echo",
                  6: "foxtrot", 7: "golf", 8: "hotel", 9: "india", 10: "juliet",
                  11: "kilo"}

    for inode in range(21, 32):
        data = recovered.get(inode)
        if data and data[:3] == b"TLM":
            seq = data[4]
            msg_len_field = data[5]
            fragments[seq] = data
            name = frag_names.get(seq, f"seq{seq}")
            print(f"    TLM fragment: {name:<9s} seq={seq:2d}  msg_len={msg_len_field:2d}  "
                  f"total={len(data)} bytes  (inode {inode})")

    # --- Step 4: Decrypt alpha/bravo/charlie ---
    print()
    flag_parts = []
    for seq in [1, 2, 3]:
        if seq not in fragments:
            print(f"[-] Missing fragment seq={seq}")
            continue

        frag = fragments[seq]
        name = frag_names[seq]
        result = decrypt_tlm_fragment(frag, xor_key)

        if result:
            offset, text = result
            print(f"[+] {name:<9s} (seq={seq}, offset={offset:2d}): '{text}'")
            flag_parts.append(text)
        else:
            print(f"[-] Failed to decrypt {name} (seq={seq})")

    # --- Step 5: Assemble flag ---
    if flag_parts:
        flag = "".join(flag_parts)
        print(f"\n{'='*60}")
        print(f"[+] FLAG: {flag}")
        print(f"{'='*60}")

        # Save to flag.txt
        with open("flag.txt", "w") as f:
            f.write(flag + "\n")
        print(f"[*] Saved to flag.txt")
    else:
        print("[-] Could not assemble flag")


if __name__ == "__main__":
    main()
